use clap::Parser;
use honk_core::Cli;

/// musl's stock malloc is slow under contention; route all Rust
/// allocations through jemalloc in the shipped binary.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// Keep the gateway's RSS high-water mark accountable at base-page
/// granularity: with transparent huge pages, the allocator's page-granular
/// returns to the OS stay backed in 2 MiB units.
#[cfg(all(feature = "jemalloc", target_os = "linux"))]
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

fn block_on_worker<F, T>(runtime: &tokio::runtime::Runtime, future: F) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    runtime.block_on(runtime.spawn(future))?
}

fn main() -> anyhow::Result<()> {
    #[cfg(all(feature = "jemalloc", target_os = "linux"))]
    disable_transparent_huge_pages()?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    block_on_worker(&runtime, async_main())
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
