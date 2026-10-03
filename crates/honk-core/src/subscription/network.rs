use super::{Subscription, fetch_body, subscription_client};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc, oneshot, watch};
use tokio::task::{JoinHandle, JoinSet};

const MAX_REQUESTS: usize = 4;
const JOIN_DEADLINE: Duration = Duration::from_secs(5);

type ThreadResult = Result<(), &'static str>;

struct Request {
    subscription: Subscription,
    reply: oneshot::Sender<anyhow::Result<Vec<u8>>>,
}

struct NetworkThread {
    requests: mpsc::Sender<Request>,
    stop: watch::Sender<bool>,
    ready: Option<oneshot::Receiver<ThreadResult>>,
    thread: Option<std::thread::JoinHandle<ThreadResult>>,
}

impl NetworkThread {
    fn start(
        build_client: impl FnOnce() -> anyhow::Result<crate::marked_http::Client> + Send + 'static,
    ) -> anyhow::Result<Self> {
        let (requests, receiver) = mpsc::channel(MAX_REQUESTS);
        let (stop, stopped) = watch::channel(false);
        let (ready, readiness) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("honk-subscriptions".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        tracing::error!(%error, "Subscription network runtime creation failed");
                        "subscription network runtime creation failed"
                    })?;
                // Default runtime drop cancels the HTTP client's spawned connection tasks and
                // waits for started blocking jobs; timeout/background shutdown would detach them.
                runtime.block_on(async move {
                    let client = build_client().map_err(|error| {
                        tracing::error!(%error, "Subscription HTTP client creation failed");
                        "subscription HTTP client creation failed"
                    })?;
                    if ready.send(Ok(())).is_err() {
                        return Ok(());
                    }
                    run(client, receiver, stopped).await
                })
            })?;
        Ok(Self {
            requests,
            stop,
            ready: Some(readiness),
            thread: Some(thread),
        })
    }

    fn join(&mut self) -> JoinHandle<ThreadResult> {
        self.stop.send_replace(true);
        let thread = self
            .thread
            .take()
            .expect("subscription thread already joining");
        tokio::task::spawn_blocking(move || {
            let result = thread
                .join()
                .unwrap_or(Err("subscription network thread panicked"));
            if let Err(error) = result {
                tracing::error!(error, "Subscription network owner failed");
            }
            result
        })
    }
}

impl Drop for NetworkThread {
    fn drop(&mut self) {
        if self.thread.is_some() {
            // Abandoned startup must still stop its runtime. Normal pause/shutdown
            // retains and awaits this join; dropping an owner never acknowledges it.
            drop(self.join());
        }
    }
}

struct State {
    active: Option<NetworkThread>,
    joining: Option<JoinHandle<ThreadResult>>,
    stopped_at: Option<Instant>,
    failure: Option<&'static str>,
}

pub(super) struct SubscriptionNetwork {
    state: Mutex<State>,
}

impl SubscriptionNetwork {
    pub(super) fn new() -> anyhow::Result<Self> {
        Self::with_client(subscription_client)
    }

    fn with_client(
        build_client: impl FnOnce() -> anyhow::Result<crate::marked_http::Client> + Send + 'static,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            state: Mutex::new(State {
                active: Some(NetworkThread::start(build_client)?),
                joining: None,
                stopped_at: None,
                failure: None,
            }),
        })
    }

    async fn await_ready(state: &mut State) -> anyhow::Result<()> {
        if let Some(error) = state.failure {
            anyhow::bail!(error);
        }
        let active = state
            .active
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("subscription network is paused"))?;
        if let Some(ready) = active.ready.as_mut() {
            let result = ready
                .await
                .unwrap_or(Err("subscription network startup failed"));
            active.ready = None;
            if let Err(error) = result {
                state.failure = Some(error);
                anyhow::bail!(error);
            }
        }
        if active
            .thread
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
        {
            state.failure = Some("subscription network exited unexpectedly");
            anyhow::bail!("subscription network exited unexpectedly");
        }
        Ok(())
    }

    pub(super) async fn ready(&self) -> anyhow::Result<()> {
        Self::await_ready(&mut *self.state.lock().await).await
    }

    pub(super) async fn fetch(&self, subscription: &Subscription) -> anyhow::Result<Vec<u8>> {
        let sender = {
            let mut state = self.state.lock().await;
            Self::await_ready(&mut state).await?;
            state.active.as_ref().unwrap().requests.clone()
        };
        // Reserve before cloning: startup overflow waits rather than losing work.
        let permit = sender
            .reserve()
            .await
            .map_err(|_| anyhow::anyhow!("subscription network is paused"))?;
        let (reply, result) = oneshot::channel();
        permit.send(Request {
            subscription: subscription.clone(),
            reply,
        });
        result
            .await
            .map_err(|_| anyhow::anyhow!("subscription network request cancelled"))?
    }

    pub(super) async fn pause(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if let Some(mut active) = state.active.take() {
            state.stopped_at = Some(Instant::now());
            state.joining = Some(active.join());
        }
        if let Some(joining) = state.joining.as_mut() {
            // The handle stays in the owner when an awaiting future is cancelled.
            let result = joining
                .await
                .unwrap_or(Err("subscription network join failed"));
            state.joining = None;
            if let Err(error) = result {
                state.failure.get_or_insert(error);
            }
            if state
                .stopped_at
                .is_some_and(|at| at.elapsed() > JOIN_DEADLINE)
            {
                state
                    .failure
                    .get_or_insert("subscription network join exceeded deadline");
            }
        }
        if let Some(error) = state.failure {
            anyhow::bail!(error);
        }
        Ok(())
    }
}

async fn run(
    client: crate::marked_http::Client,
    mut requests: mpsc::Receiver<Request>,
    mut stop: watch::Receiver<bool>,
) -> ThreadResult {
    // One marked client serves every in-flight request task.
    let client = std::sync::Arc::new(client);
    let mut active = JoinSet::new();
    let mut result = Ok(());
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => break,
            completed = active.join_next(), if !active.is_empty() => {
                if completed.is_some_and(|result| result.is_err()) {
                    result = Err("subscription network request task panicked");
                    break;
                }
            }
            request = requests.recv(), if active.len() < MAX_REQUESTS => {
                let Some(Request { subscription, mut reply }) = request else { break; };
                let client = client.clone();
                active.spawn(async move {
                    tokio::select! {
                        biased;
                        _ = reply.closed() => {}
                        body = fetch_body(&client, &subscription) => { let _ = reply.send(body); }
                    }
                });
            }
        }
    }
    requests.close();
    while requests.try_recv().is_ok() {}
    active.abort_all();
    while let Some(completed) = active.join_next().await {
        if completed.is_err_and(|error| !error.is_cancelled()) {
            result = Err("subscription network request task panicked");
        }
    }
    result
}

#[cfg(test)]
mod tests;
