use super::tcx_aux::PreparedAux;
use super::*;
use crate::control::{ShutdownIntent, TASK_BOOKKEEPING};
use futures::FutureExt as _;
use std::panic::AssertUnwindSafe;
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinHandle;

pub(super) struct AuxTasks {
    jobs: Mutex<Vec<JoinHandle<anyhow::Result<()>>>>,
    shutdown: Arc<ShutdownIntent>,
    _memory: MemoryReservation,
}

pub(super) struct AuxStartup {
    activate: Option<oneshot::Sender<()>>,
    ready: oneshot::Receiver<anyhow::Result<()>>,
}

struct Run {
    aux: PreparedAux,
    driver: PacketDriver,
    endpoints: PacketEndpoints,
    gateway: Arc<GatewayPublisher>,
    admission: Arc<AtomicBool>,
    shutdown: Arc<ShutdownIntent>,
    activate: oneshot::Receiver<()>,
    ready: oneshot::Sender<anyhow::Result<()>>,
}

impl Run {
    async fn drive(self) -> anyhow::Result<()> {
        let stop = self.shutdown;
        let result = AssertUnwindSafe(self.aux.run(
            self.driver,
            self.endpoints,
            self.gateway,
            self.admission,
            Arc::clone(&stop),
            self.activate,
            self.ready,
        ))
        .catch_unwind()
        .await
        .unwrap_or_else(|_| Err(anyhow::anyhow!("auxiliary TUN task panicked")));
        if result.is_err() {
            stop.request();
        }
        result
    }
}

impl AuxTasks {
    pub(super) fn reserve(
        count: usize,
        root: &Arc<MemoryBudget>,
        shutdown: Arc<ShutdownIntent>,
    ) -> anyhow::Result<Self> {
        fn future_bytes<F: Future>(_: fn(Run) -> F) -> usize {
            size_of::<F>()
        }
        // Two startup channels and their wakers can coexist with the running Tokio task.
        let task_bytes = future_bytes(Run::drive)
            + 3 * TASK_BOOKKEEPING
            + size_of::<AuxStartup>()
            + size_of::<JoinHandle<anyhow::Result<()>>>();
        let memory = root
            .reserve(
                task_bytes
                    .checked_mul(count)
                    .context("auxiliary task size overflow")?,
            )
            .context("auxiliary task memory capacity")?;
        Ok(Self {
            jobs: Mutex::new(Vec::with_capacity(count)),
            shutdown,
            _memory: memory,
        })
    }

    pub(super) fn stop(&self) {
        self.shutdown.request();
    }

    pub(super) async fn join(&self) -> anyhow::Result<()> {
        let mut jobs = self.jobs.lock().await;
        let mut failure = None;
        while let Some(job) = jobs.last_mut() {
            let result = job
                .await
                .context("joining auxiliary TUN task")
                .and_then(|r| r);
            jobs.pop();
            fold_capture_result(&mut failure, result);
        }
        failure.map_or(Ok(()), Err)
    }
}

impl Runtime {
    pub(super) fn start_auxiliary(
        &self,
        prepared: Vec<PreparedAux>,
        drivers: &mut Vec<PacketDriver>,
        shared_runtime: &tokio::runtime::Handle,
    ) -> Vec<AuxStartup> {
        let mut startup = Vec::with_capacity(prepared.len());
        if prepared.is_empty() {
            return startup;
        }
        let tasks = self
            .workers
            .auxiliary
            .get()
            .expect("funded auxiliary tasks");
        let gateway = self.gateway.as_ref().expect("auxiliary gateway publisher");
        let mut jobs = tasks.jobs.try_lock().expect("exclusive auxiliary startup");
        for aux in prepared {
            let i = drivers
                .iter()
                .position(|d| d.scope() == aux.scope())
                .expect("auxiliary scope driver");
            let (open, activate) = oneshot::channel();
            let (ready, status) = oneshot::channel();
            let run = Run {
                aux,
                driver: drivers.swap_remove(i),
                endpoints: self.endpoints.clone(),
                gateway: Arc::clone(gateway),
                admission: Arc::clone(&self.admission),
                shutdown: Arc::clone(&tasks.shutdown),
                activate,
                ready,
            };
            jobs.push(shared_runtime.spawn(run.drive()));
            startup.push(AuxStartup {
                activate: Some(open),
                ready: status,
            });
        }
        startup
    }

    pub(super) async fn activate_auxiliary(
        &mut self,
        mut startup: Vec<AuxStartup>,
        shutdown: &ShutdownIntent,
    ) -> anyhow::Result<()> {
        if startup.is_empty() {
            return Ok(());
        }
        for task in &mut startup {
            task.activate
                .take()
                .unwrap()
                .send(())
                .map_err(|_| anyhow::anyhow!("auxiliary TUN stopped before activation"))?;
        }
        let ready = async move {
            for task in startup {
                task.ready
                    .await
                    .context("auxiliary TUN did not report readiness")??;
            }
            anyhow::Ok(())
        };
        let timer = None;
        let changed = self.polling.notification();
        tokio::pin!(ready, timer, changed);
        loop {
            tokio::select! {
                biased;
                () = shutdown.wait() => anyhow::bail!("shutdown during auxiliary TUN activation"),
                result = &mut ready => { result?; break; }
                result = poll_fn(|cx| self.poll_service(cx, shutdown, timer.as_mut(), true, changed.as_mut())) => {
                    result?;
                    // Auxiliary capture is Endpoint-only; no pending Core reader needs discarding.
                    self.policy_recheck = false;
                    tokio::task::yield_now().await;
                }
            }
        }
        let _start = shutdown.lock_capture_start()?;
        ensure!(
            self.admission.load(Ordering::Acquire),
            "XDP capture closed during auxiliary activation"
        );
        self.endpoints.capture_ready()?;
        Ok(())
    }
}
