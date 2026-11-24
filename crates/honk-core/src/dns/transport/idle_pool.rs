use std::future::Future;
use std::time::Duration;

const MAX_IDLE_STREAMS: usize = 4;

pub(super) enum IdlePoolState {
    Open,
    Closed,
}

pub(super) struct IdleStream<S> {
    io: S,
    // Each routed query on a reused stream needs a fresh wire ID.
    next_id: u16,
}

/// Pop an idle stream or dial a fresh one, run one length-prefixed exchange,
/// and return the stream to the pool on success (DoT / plain-TCP shared shape).
pub(super) async fn idle_pool_exchange<S, Dial, DialFut>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<IdleStream<S>>>,
    dial: Dial,
    raw_query: &[u8],
    query_timeout: Duration,
    reporter: Option<&honk_outbound::group::ScoreReporter>,
    routed: bool,
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
        None => IdleStream {
            io: dial().await?,
            next_id: 0,
        },
    };
    if let Some(reporter) = reporter {
        reporter.setup_succeeded();
    }
    let resp = super::framing::exchange_length_prefixed_reported(
        &mut stream.io,
        raw_query,
        query_timeout,
        reporter,
        routed.then_some(stream.next_id),
    )
    .await?;
    if routed {
        let Some(next_id) = stream.next_id.checked_add(1) else {
            return Ok(resp);
        };
        stream.next_id = next_id;
    }
    let mut guard = idle.lock();
    if guard.len() < MAX_IDLE_STREAMS {
        guard.push(stream);
    }
    drop(lifecycle);
    Ok(resp)
}

pub(super) async fn close_idle_pool<S>(
    lifecycle: &tokio::sync::RwLock<IdlePoolState>,
    idle: &parking_lot::Mutex<Vec<IdleStream<S>>>,
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
        let _ = tokio::time::timeout(timeout, stream.io.shutdown()).await;
    }
}
