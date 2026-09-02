use clap::Parser;
use honk_core::Cli;

/// musl's stock malloc is slow under contention; route all Rust
/// allocations through mimalloc in the shipped binary.
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(all(feature = "mimalloc", target_os = "linux"))]
fn disable_transparent_huge_pages() -> std::io::Result<()> {
    // SAFETY: prctl receives fixed integer arguments and no pointers.
    let result = unsafe {
        libc::prctl(
            libc::PR_SET_THP_DISABLE,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(feature = "mimalloc")]
fn mimalloc_collect_period(value: Option<&str>) -> Option<std::time::Duration> {
    let seconds = value.and_then(|value| value.parse().ok()).unwrap_or(60);
    (seconds > 0).then(|| std::time::Duration::from_secs(seconds))
}

#[cfg(feature = "mimalloc")]
std::thread_local! {
    static LAST_MI_COLLECT: std::cell::Cell<Option<std::time::Instant>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(feature = "mimalloc")]
fn collect_mimalloc_on_idle<F>(
    now: std::time::Instant,
    period: std::time::Duration,
    collect: F,
) -> bool
where
    F: FnOnce(),
{
    LAST_MI_COLLECT.with(|last_collect| match last_collect.get() {
        None => {
            last_collect.set(Some(now));
            false
        }
        Some(previous) if now.saturating_duration_since(previous) >= period => {
            last_collect.set(Some(now));
            collect();
            true
        }
        Some(_) => false,
    })
}

#[cfg(feature = "mimalloc")]
const OWNER_SWEEP_RENDEZVOUS_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(5);
#[cfg(feature = "mimalloc")]
const OWNER_SWEEP_MAX_ROUNDS: usize = 3;
#[cfg(feature = "mimalloc")]
const OWNER_SWEEP_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

#[cfg(feature = "mimalloc")]
#[derive(Clone)]
struct OwnerCollector {
    period: std::time::Duration,
    worker_count: usize,
    parked_workers: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

#[cfg(feature = "mimalloc")]
struct SweepState {
    workers: std::collections::HashSet<std::thread::ThreadId>,
    released: bool,
}

#[cfg(feature = "mimalloc")]
impl OwnerCollector {
    async fn run(self) {
        let mut interval = tokio::time::interval(self.period);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        interval.tick().await;
        loop {
            interval.tick().await;
            if !self.workers_idle_for_sweep() {
                continue;
            }
            let covered = self.sweep().await;
            if covered < self.worker_count {
                tracing::warn!(
                    covered,
                    expected = self.worker_count,
                    "mimalloc owner sweep could not reach every Tokio worker"
                );
            }
        }
    }

    fn workers_idle_for_sweep(&self) -> bool {
        // The interval task itself occupies one worker.
        self.parked_workers
            .load(std::sync::atomic::Ordering::Relaxed)
            >= self.worker_count.saturating_sub(1)
    }

    async fn sweep(&self) -> usize {
        let covered = std::sync::Arc::new(parking_lot::Mutex::new(
            std::collections::HashSet::with_capacity(self.worker_count),
        ));
        for round in 0..OWNER_SWEEP_MAX_ROUNDS {
            if covered.lock().len() == self.worker_count {
                break;
            }
            self.sweep_round(&covered).await;
            if round + 1 < OWNER_SWEEP_MAX_ROUNDS && covered.lock().len() < self.worker_count {
                tokio::time::sleep(OWNER_SWEEP_RETRY_DELAY.min(self.period)).await;
            }
        }
        covered.lock().len()
    }

    async fn sweep_round(
        &self,
        covered: &std::sync::Arc<
            parking_lot::Mutex<std::collections::HashSet<std::thread::ThreadId>>,
        >,
    ) {
        // Blocking here makes pending tasks occupy distinct workers; collection stays
        // in each worker's ordinary idle callback after these tasks return.
        let rendezvous = std::sync::Arc::new((
            parking_lot::Mutex::new(SweepState {
                workers: std::collections::HashSet::with_capacity(self.worker_count),
                released: false,
            }),
            parking_lot::Condvar::new(),
        ));
        let mut tasks = Vec::with_capacity(self.worker_count);
        for _ in 0..self.worker_count {
            let collector = self.clone();
            let rendezvous = std::sync::Arc::clone(&rendezvous);
            let covered = std::sync::Arc::clone(covered);
            tasks.push(tokio::spawn(async move {
                collector.rendezvous_and_mark(&rendezvous, &covered);
            }));
        }
        for task in tasks {
            let _ = task.await;
        }
    }

    fn rendezvous_and_mark(
        &self,
        rendezvous: &(parking_lot::Mutex<SweepState>, parking_lot::Condvar),
        covered: &parking_lot::Mutex<std::collections::HashSet<std::thread::ThreadId>>,
    ) {
        let (state, wake) = rendezvous;
        let deadline = std::time::Instant::now() + OWNER_SWEEP_RENDEZVOUS_TIMEOUT;
        let worker = std::thread::current().id();
        let mut state = state.lock();
        state.workers.insert(worker);
        if state.workers.len() == self.worker_count {
            state.released = true;
            wake.notify_all();
        }
        while !state.released {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() || wake.wait_for(&mut state, remaining).timed_out() {
                state.released = true;
                wake.notify_all();
                break;
            }
        }
        drop(state);
        covered.lock().insert(worker);
    }
}

#[cfg(feature = "mimalloc")]
fn install_idle_collector<F>(
    builder: &mut tokio::runtime::Builder,
    period: std::time::Duration,
    collect: F,
) -> std::sync::Arc<std::sync::atomic::AtomicUsize>
where
    F: Fn() + Send + Sync + 'static,
{
    builder.on_thread_start(|| {
        LAST_MI_COLLECT.with(|last_collect| {
            last_collect.set(Some(std::time::Instant::now()));
        });
    });
    let parked_workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let parked = std::sync::Arc::clone(&parked_workers);
    builder.on_thread_park(move || {
        collect_mimalloc_on_idle(std::time::Instant::now(), period, &collect);
        parked.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    });
    let unparked = std::sync::Arc::clone(&parked_workers);
    builder.on_thread_unpark(move || {
        let previous = unparked.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        debug_assert!(previous > 0);
    });
    parked_workers
}
fn block_on_worker<F, T>(runtime: &tokio::runtime::Runtime, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    runtime.block_on(runtime.spawn(future))?
}

fn main() -> anyhow::Result<()> {
    #[cfg(all(feature = "mimalloc", target_os = "linux"))]
    disable_transparent_huge_pages()?;

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all();

    #[cfg(feature = "mimalloc")]
    let collector = {
        let value = std::env::var("HONK_MI_COLLECT_SECS").ok();
        mimalloc_collect_period(value.as_deref()).map(|period| {
            let parked_workers = install_idle_collector(&mut builder, period, || {
                // SAFETY: callbacks run on the worker owning this default heap.
                unsafe { libmimalloc_sys::mi_collect(true) };
            });
            (period, parked_workers)
        })
    };

    let runtime = builder.build()?;
    #[cfg(feature = "mimalloc")]
    let sweep = collector.map(|(period, parked_workers)| {
        runtime.spawn(
            OwnerCollector {
                period,
                worker_count: runtime.metrics().num_workers(),
                parked_workers,
            }
            .run(),
        )
    });
    let result = block_on_worker(&runtime, async_main());
    #[cfg(feature = "mimalloc")]
    if let Some(sweep) = sweep {
        sweep.abort();
    }
    result
}

async fn async_main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if cli.command.is_some() {
        return honk_core::handle_clash_command(&cli).await;
    }

    // Mirror fatal failures through tracing: the anyhow return only reaches
    // stderr, but deployments commonly collect just the log file.
    let result = honk_core::run(cli).await;
    if let Err(error) = &result {
        tracing::error!("fatal error, shutting down: {error:#}");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "mimalloc")]
    #[test]
    fn idle_collection_delays_first_park_and_obeys_per_thread_cooldown() {
        let start = std::time::Instant::now();
        let period = std::time::Duration::from_secs(10);
        let mut collections = 0;
        LAST_MI_COLLECT.with(|last_collect| last_collect.set(None));

        assert!(!collect_mimalloc_on_idle(start, period, || collections += 1));
        assert!(!collect_mimalloc_on_idle(
            start + std::time::Duration::from_secs(9),
            period,
            || collections += 1,
        ));
        let first_due = start + period;
        assert!(collect_mimalloc_on_idle(first_due, period, || {
            LAST_MI_COLLECT.with(|last_collect| assert_eq!(last_collect.get(), Some(first_due)));
            collections += 1;
        }));
        assert!(!collect_mimalloc_on_idle(
            first_due + std::time::Duration::from_secs(9),
            period,
            || collections += 1,
        ));
        assert!(collect_mimalloc_on_idle(first_due + period, period, || {
            collections += 1;
        }));

        assert_eq!(collections, 2);
        LAST_MI_COLLECT.with(|last_collect| last_collect.set(None));
    }

    #[cfg(feature = "mimalloc")]
    #[test]
    fn idle_collection_runs_on_each_worker_thread() {
        use parking_lot::{Condvar, Mutex};
        use std::collections::HashSet;
        use std::sync::Arc;

        let collector_threads = Arc::new((Mutex::new(HashSet::new()), Condvar::new()));
        let callback_threads = Arc::clone(&collector_threads);

        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(4).enable_all();
        let _parked_workers =
            install_idle_collector(&mut builder, std::time::Duration::ZERO, move || {
                let (threads, wake) = &*callback_threads;
                threads.lock().insert(std::thread::current().id());
                wake.notify_all();
            });
        let runtime = builder.build().unwrap();
        let worker_count = runtime.metrics().num_workers();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (threads, wake) = &*collector_threads;
        let mut observed = threads.lock();
        while observed.len() < worker_count {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "not every runtime worker parked");
            let timeout = wake.wait_for(&mut observed, remaining);
            assert!(!timeout.timed_out() || observed.len() == worker_count);
        }

        assert_eq!(observed.len(), worker_count);
    }

    #[cfg(feature = "mimalloc")]
    #[test]
    fn periodic_sweep_collects_workers_that_remain_parked() {
        use parking_lot::{Condvar, Mutex};
        use std::collections::HashSet;
        use std::sync::Arc;

        let observed = Arc::new((Mutex::new(HashSet::new()), Condvar::new()));
        let callback_observed = Arc::clone(&observed);
        let period = std::time::Duration::ZERO;
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(4).enable_all();
        let parked_workers = install_idle_collector(&mut builder, period, move || {
            let (threads, wake) = &*callback_observed;
            threads.lock().insert(std::thread::current().id());
            wake.notify_all();
        });
        let runtime = builder.build().unwrap();

        let worker_count = runtime.metrics().num_workers();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while parked_workers.load(std::sync::atomic::Ordering::Relaxed) < worker_count {
            assert!(
                std::time::Instant::now() < deadline,
                "not every runtime worker parked"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let started = observed.0.lock().clone();
        assert_eq!(started.len(), worker_count);
        observed.0.lock().clear();
        let collector = OwnerCollector {
            period,
            worker_count,
            parked_workers,
        };
        assert_eq!(runtime.block_on(collector.sweep()), worker_count);

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let (threads, wake) = &*observed;
        let mut observed = threads.lock();
        while observed.len() < worker_count {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            assert!(!remaining.is_zero(), "not every runtime worker collected");
            let timeout = wake.wait_for(&mut observed, remaining);
            assert!(!timeout.timed_out() || observed.len() == worker_count);
        }
        assert_eq!(*observed, started);
    }

    #[cfg(feature = "mimalloc")]
    #[test]
    fn periodic_sweep_waits_until_other_workers_are_parked() {
        let parked_workers = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(2));
        let collector = OwnerCollector {
            period: std::time::Duration::from_secs(60),
            worker_count: 4,
            parked_workers: std::sync::Arc::clone(&parked_workers),
        };

        assert!(!collector.workers_idle_for_sweep());
        parked_workers.store(3, std::sync::atomic::Ordering::Relaxed);
        assert!(collector.workers_idle_for_sweep());
    }
    #[test]
    fn top_level_future_runs_on_a_runtime_worker() {
        let caller = std::thread::current().id();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();

        let worker = block_on_worker(&runtime, async {
            Ok::<_, anyhow::Error>(std::thread::current().id())
        })
        .unwrap();

        assert_ne!(caller, worker);
    }

    #[test]
    fn explicit_runtime_keeps_time_and_io_enabled() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let client = tokio::spawn(async move { tokio::net::TcpStream::connect(address).await });
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), address.ip());
            client.await.unwrap().unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        });
    }
}
