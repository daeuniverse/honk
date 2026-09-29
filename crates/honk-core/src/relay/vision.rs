//! Relay for unencrypted Vision carriers.
//!
//! Copies in userspace until both directions are Direct, then lends the
//! carrier's TCP socket to the ordinary bidirectional splice engine. The
//! Vision and TLS stack stays owned by the relay throughout, so any splice
//! setup failure before bytes move resumes the same copy path.

use std::net::SocketAddr;
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};

use honk_outbound::proxy::vless::VisionSplice;
use honk_outbound::transport_quality::RawObserver;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::debug;

use super::splice::{self, SpliceError};
use super::{Park, RelayError, RelayProgress, RelayStats};

impl<'a> Park<'a> {
    fn new(gate: &'a (dyn Fn() -> bool + Sync)) -> Self {
        Self {
            gate,
            waiting: Default::default(),
            taken: AtomicBool::new(false),
        }
    }
}

/// Bytes a connection must have moved before it pays for pipe setup.
// ponytail: fixed threshold; make it adaptive only if measured flows mis-sort.
const SPLICE_AFTER_BYTES: u64 = 256 * 1024;

pub(super) async fn relay_vision(
    client: &mut TcpStream,
    mut proxy: VisionSplice,
    client_addr: SocketAddr,
    target_addr: SocketAddr,
    progress: RelayProgress,
) -> anyhow::Result<RelayStats> {
    let start = tokio::time::Instant::now();
    debug!("Vision relay started: {} → {}", client_addr, target_addr);
    let result = relay_phases(client, &mut proxy, &progress).await;
    let _ = client.shutdown().await;
    let _ = proxy.shutdown().await;
    // Every phase counts into the same connection counters.
    let totals = result.map(|()| {
        (
            progress.upload.load(Ordering::Relaxed),
            progress.download.load(Ordering::Relaxed),
        )
    });
    super::relay_outcome(totals, start, client_addr, target_addr)
}

async fn relay_phases(
    client: &mut TcpStream,
    proxy: &mut VisionSplice,
    progress: &RelayProgress,
) -> Result<(), RelayError> {
    let ready = proxy.ready_signal();
    let gate = || ready.load(Ordering::Relaxed) && moved(progress) >= SPLICE_AFTER_BYTES;
    let park = splice::splice_available().then(|| Park::new(&gate));
    copy(client, proxy, progress, park.as_ref()).await?;
    if !park.as_ref().is_some_and(Park::taken) {
        return Ok(());
    }
    if let Some((raw, mut observer)) = proxy.raw_parts() {
        match splice_observed(client, raw, &mut observer, progress).await {
            Ok(()) => return Ok(()),
            Err(error) => error.into_fallback()?,
        }
    }
    copy(client, proxy, progress, None).await
}

async fn copy(
    client: &mut TcpStream,
    proxy: &mut VisionSplice,
    progress: &RelayProgress,
    park: Option<&Park<'_>>,
) -> Result<(), RelayError> {
    let (mut client, mut proxy) = super::relay_io_pair(client, proxy, &phase_progress(progress));
    super::copy_phase(&mut client, &mut proxy, park)
        .await
        .map(drop)
}

/// Splices the lent socket while sampling its carrier pressure whenever the
/// pumps make progress, as `ObservedTcp` would for copied bytes.
async fn splice_observed(
    client: &TcpStream,
    raw: &TcpStream,
    observer: &mut RawObserver<'_>,
    progress: &RelayProgress,
) -> Result<(), SpliceError> {
    let mut seen = moved(progress);
    let mut run = pin!(splice::run(client, raw, Some(phase_progress(progress))));
    std::future::poll_fn(|cx| {
        let poll = run.as_mut().poll(cx);
        if moved(progress) != seen {
            seen = moved(progress);
            observer.observe();
        }
        poll
    })
    .await
    .map(drop)
}

fn moved(progress: &RelayProgress) -> u64 {
    progress.upload.load(Ordering::Relaxed) + progress.download.load(Ordering::Relaxed)
}

/// The first upstream byte fires the response callback once per connection,
/// whichever phase carries it.
fn phase_progress(progress: &RelayProgress) -> RelayProgress {
    let mut phase = progress.clone();
    if progress.download.load(Ordering::Relaxed) != 0 {
        phase.first_response = None;
    }
    phase
}

#[cfg(test)]
mod tests;
