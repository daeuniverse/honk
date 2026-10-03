use std::future::Future;
use std::time::Duration;

const MAX_IDLE_STREAMS: usize = 4;

pub(super) enum IdlePoolState {
    Open,
    Closed,
}

/// Pop an idle stream or dial a fresh one, run one length-prefixed exchange,
/// and return the stream to the pool on success (DoT / plain-TCP shared shape).
pub(super) async fn idle_pool_exchange<S, Dial, DialFut>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<S>>,
    dial: Dial,
    raw_query: &[u8],
    query_timeout: Duration,
    reporter: Option<&honk_outbound::group::ScoreReporter>,
) -> anyhow::Result<Vec<u8>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    Dial: FnOnce() -> DialFut,
    DialFut: Future<Output = anyhow::Result<S>>,
{
    let lifecycle = lifecycle.read().await;
    match *lifecycle {
        IdlePoolState::Open => {}
        IdlePoolState::Closed => anyhow::bail!("DNS transport pool is closed"),
    }
    let taken = idle.lock().pop();
    let mut stream = match taken {
        Some(s) => {
            super::lifecycle::attached();
            s
        }
        None => dial().await?,
    };
    if let Some(reporter) = reporter {
        reporter.setup_succeeded();
    }
    let resp = super::framing::exchange_length_prefixed_reported(
        &mut stream,
        raw_query,
        query_timeout,
        reporter,
    )
    .await?;
    let mut guard = idle.lock();
    if guard.len() < MAX_IDLE_STREAMS {
        guard.push(stream);
    }
    drop(lifecycle);
    Ok(resp)
}

pub(super) async fn close_idle_pool<S>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<S>>,
    timeout: Duration,
) where
    S: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    let mut lifecycle = lifecycle.write().await;
    match *lifecycle {
        IdlePoolState::Closed => return,
        IdlePoolState::Open => *lifecycle = IdlePoolState::Closed,
    }
    let streams = std::mem::take(&mut *idle.lock());
    for mut stream in streams {
        let _ = tokio::time::timeout(timeout, stream.shutdown()).await;
    }
}
