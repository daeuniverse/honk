//! Queue tasks hold the driving rights. The coordinator keeps every queue file alive
//! through route withdrawal and the last join: closing a middle FD renumbers Linux queues.

mod queue;

use super::*;
use crate::control::{
    dns_listener::PreparedDnsBind,
    netstack::{PacketRealm, capture_tun_realm},
};
use queue::QueueIo;
use tokio::{
    sync::{oneshot, watch},
    task::JoinSet,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Starting,
    Active,
    Closing,
    Joined,
}

struct Capture {
    phase: watch::Sender<Phase>,
    open: Arc<AtomicBool>,
}

impl Capture {
    fn close(&self) {
        self.phase.send_if_modified(|phase| {
            if matches!(*phase, Phase::Starting | Phase::Active) {
                self.open.store(false, Ordering::Release);
                *phase = Phase::Closing;
                true
            } else {
                false
            }
        });
    }

    async fn closed(&self) {
        let mut state = self.phase.subscribe();
        let _ = state
            .wait_for(|phase| matches!(phase, Phase::Closing | Phase::Joined))
            .await;
    }

    fn publish<T>(
        &self,
        routes: impl FnOnce() -> anyhow::Result<T>,
        running: impl FnOnce() -> io::Result<()>,
    ) -> anyhow::Result<T> {
        let mut result = None;
        self.phase.send_if_modified(|phase| {
            if *phase != Phase::Starting {
                return false;
            }
            result = Some(routes().and_then(|value| {
                self.open.store(true, Ordering::Release);
                running()?;
                Ok(value)
            }));
            if result.as_ref().is_some_and(Result::is_ok) {
                *phase = Phase::Active;
            } else {
                self.open.store(false, Ordering::Release);
                *phase = Phase::Closing;
            }
            true
        });
        result.context("TUN worker closed before publication")?
    }
}

struct CloseOnDrop(Arc<Capture>);
impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.0.close();
    }
}

async fn publish_after_ready<T>(
    queues: Vec<oneshot::Receiver<()>>,
    supervisor: impl Future<Output = anyhow::Result<()>>,
    publish: impl FnOnce() -> anyhow::Result<T>,
) -> anyhow::Result<T> {
    let workers = async {
        for ready in queues {
            ready.await.context("TUN worker failed before readiness")?;
        }
        Ok(())
    };
    tokio::try_join!(workers, supervisor)?;
    publish()
}

struct Worker {
    // Fence the device before returning an abandoned driver on unwind.
    fence: CloseOnDrop,
    driver: PacketDriver,
    queue: QueueIo,
    realm: PacketRealm,
    endpoints: PacketEndpoints,
}

impl Worker {
    async fn run<T: AsRawFd>(
        mut self,
        device: Arc<AsyncFd<T>>,
        ready: oneshot::Sender<()>,
    ) -> anyhow::Result<()> {
        let gate = &self.fence.0;
        let mut phases = gate.phase.subscribe();
        let mut ready = Some(ready);
        let timer = None;
        tokio::pin!(timer);
        loop {
            let phase = *phases.borrow_and_update();
            if phase == Phase::Joined {
                return Ok(());
            }
            tokio::select! {
                biased;
                changed = phases.changed() => { changed.context("TUN coordinator stopped")?; continue; }
                result = poll_fn(|cx| {
                    let now = Instant::now();
                    let more = if self.endpoints.is_closing() || phase == Phase::Closing {
                        if phase != Phase::Closing { gate.close(); }
                        self.driver.service_closing(cx, now)
                    } else if phase == Phase::Active && !gate.open.load(Ordering::Acquire) {
                        self.driver.service_closing(cx, now)
                    } else if phase == Phase::Active {
                        self.driver.begin_turn(now);
                        let result = self.queue.poll(cx, &device, &mut self.driver,
                            &self.endpoints, &self.realm, &gate.open, now);
                        if result.is_err() { gate.close(); }
                        self.driver.finish_turn(cx, Instant::now());
                        result?
                    } else {
                        self.driver.service(cx, now)
                    };
                    if let Some(ready) = ready.take() { let _ = ready.send(()); }
                    if more || poll_deadline(timer.as_mut(), self.driver.deadline(), cx).is_ready() {
                        Poll::Ready(Ok::<(), anyhow::Error>(()))
                    } else { Poll::Pending }
                }) => { result?; }
            }
            tokio::task::yield_now().await;
        }
    }
}

pub(super) async fn run(
    plane: ControlPlane,
    config: &Config,
    budget: Arc<MemoryBudget>,
    admission: Arc<AtomicBool>,
    dns: Option<PreparedDnsBind>,
    capacity: usize,
) -> (Option<ControlPlane>, anyhow::Result<()>) {
    let tun = config
        .datapath
        .as_ref()
        .and_then(|dp| dp.tun.as_ref())
        .expect("validated TUN");
    let count = usize::from(tun.queues);
    let shutdown = plane.shutdown_intent();
    let prepared = (|| -> anyhow::Result<_> {
        let fixed = count
            * (size_of::<Arc<AsyncFd<TunDevice>>>()
                + size_of::<AsyncFd<TunDevice>>()
                + size_of::<oneshot::Receiver<()>>()
                + 1024)
            + size_of::<Capture>();
        let memory = budget
            .reserve(fixed)
            .context("TUN queue descriptors and task registrations exceed budget")?;
        let queues = QueueIo::prepare(count, &budget)?;
        let (realm, owners) =
            capture_tun_realm(u32::from(tun.mtu), count, STANDALONE_TX_CAPS, &budget)?;
        realm.install_admission_fence(Arc::clone(&admission))?;
        Ok((memory, queues, realm, owners))
    })();
    let (_memory, queues, realm, owners) = match prepared {
        Ok(value) => value,
        Err(error) => return (Some(plane), Err(error)),
    };
    let (mut setup, devices, guarded) = match TunSetup::prepare(
        config,
        tun.queues,
        #[cfg(feature = "packet-ebpf")]
        None,
    ) {
        Ok(value) => value,
        Err(error) => return (Some(plane), Err(error)),
    };
    let registered = devices
        .into_iter()
        .map(|device| {
            // SAFETY: TunDevice retains the same owned queue file until deregistration.
            unsafe { AsyncFd::register(device) }
                .map(Arc::new)
                .map_err(io::Error::from)
        })
        .collect::<io::Result<Vec<_>>>();
    let devices = match registered {
        Ok(registered) => registered,
        Err(error) => return (Some(plane), Err(finish_failed_setup(setup, error.into()))),
    };
    let scope = realm.scope();
    let (endpoints, mut owner, drivers) = match PacketEndpoints::start_driven(
        plane,
        vec![(realm.clone(), owners)],
        capacity,
        dns,
        scope,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            drop(devices);
            return (None, Err(finish_failed_setup(setup, error)));
        }
    };
    let gate = Arc::new(Capture {
        phase: watch::channel(Phase::Starting).0,
        open: admission,
    });
    let _coordinator_fence = CloseOnDrop(Arc::clone(&gate));
    let mut workers = JoinSet::new();
    let mut acks = Vec::with_capacity(count);
    let mut joined = None;
    let mut outcome = async {
        ensure!(devices.len() == count && drivers.len() == count && queues.len() == count, "incomplete TUN queue set");
        for (index, ((device, driver), queue)) in devices.iter().zip(drivers).zip(queues).enumerate() {
            ensure!(driver.worker() == index && driver.scope() == scope, "TUN queue owner mismatch");
            let (ready, ack) = oneshot::channel();
            let worker = Worker { driver, queue, realm: realm.clone(), endpoints: endpoints.clone(), fence: CloseOnDrop(Arc::clone(&gate)) };
            let task = worker.run(Arc::clone(device), ready);
            let memory = budget.reserve(std::mem::size_of_val(&task)).context("TUN worker future exceeds budget")?;
            workers.spawn(async move { let _memory = memory; task.await });
            acks.push(ack);
        }
        let mut topology = tokio::select! {
            biased;
            _ = shutdown.wait() => anyhow::bail!("TUN shutdown before capture publication"),
            _ = gate.closed() => anyhow::bail!("TUN worker stopped before capture publication"),
            value = publish_after_ready(acks, poll_fn(|cx| owner.poll_ready(cx)), || {
                gate.publish(|| {
                    ensure!(!endpoints.is_closing() && !shutdown.requested(), "TUN closed before capture publication");
                    let topology = setup.activate(devices.iter().map(|io| io.get_ref()))?;
                    // SAFETY: Topology retains its subscribed file for the whole registration.
                    let mut watcher = unsafe { AsyncFd::register(topology) }.map_err(io::Error::from)?;
                    ensure!(!watcher.get_mut().check_changed()?, "TUN topology changed before publication");
                    ensure!(!endpoints.is_closing() && !shutdown.requested(), "TUN closed during capture publication");
                    Ok(watcher)
                }, || endpoints.capture_ready())
            }) => value?,
        };
        drop(guarded);
        tracing::info!(queues = count, "TUN datapath ready");
        if let Err(error) = libsystemd::daemon::notify(false, &[libsystemd::daemon::NotifyState::Ready]) {
            tracing::warn!(%error, "sd_notify readiness failed");
        }
        tokio::select! {
            value = poll_fn(|cx| owner.poll_join_plane(cx)) => joined = Some(value),
            _ = shutdown.wait() => {},
            _ = gate.closed() => {},
            value = poll_fn(|cx| {
                match poll_topology(&mut topology, cx, Topology::check_tun_changed)? {
                    Poll::Ready(true) => Poll::Ready(Err(anyhow::anyhow!("TUN topology changed; restart required"))),
                    Poll::Ready(false) => { cx.waker().wake_by_ref(); Poll::Pending }
                    Poll::Pending => Poll::Pending,
                }
            }) => return value,
        }
        Ok(())
    }.await;
    gate.close();
    if let Err(error) = setup.close_capture(devices[0].get_ref()) {
        record_error(&mut outcome, error);
    }
    endpoints.close();
    if joined.is_none() && !owner.is_joined() {
        joined = Some(owner.join_plane().await);
    }
    gate.phase.send_replace(Phase::Joined);
    while let Some(worker) = workers.join_next().await {
        if let Err(error) = worker
            .map_err(anyhow::Error::from)
            .and_then(|result| result)
        {
            record_error(&mut outcome, error);
        }
    }
    drop(devices);
    let plane = match joined {
        Some(Ok((plane, result))) => {
            if let Err(error) = result {
                record_error(&mut outcome, error);
            }
            Some(plane)
        }
        Some(Err(error)) => {
            record_error(&mut outcome, error);
            None
        }
        None => None,
    };
    if let Err(error) = setup.finish(outcome.is_ok()) {
        record_error(&mut outcome, error);
    }
    (plane, outcome)
}

fn record_error(outcome: &mut anyhow::Result<()>, error: anyhow::Error) {
    *outcome = Err(match std::mem::replace(outcome, Ok(())) {
        Ok(()) => error,
        Err(original) => original.context(error),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[tokio::test]
    async fn routes_wait_for_every_queue_and_supervisor() {
        let (first, one) = oneshot::channel();
        let (last, two) = oneshot::channel();
        let (supervisor, started) = oneshot::channel();
        let captures = Cell::new(0);
        let start = publish_after_ready(
            vec![one, two],
            async {
                started.await?;
                Ok(())
            },
            || {
                captures.set(captures.get() + 1);
                Ok(())
            },
        );
        tokio::pin!(start);
        first.send(()).unwrap();
        supervisor.send(()).unwrap();
        assert!(futures::poll!(&mut start).is_pending());
        assert_eq!(captures.get(), 0);
        last.send(()).unwrap();
        start.await.unwrap();
        assert_eq!(captures.get(), 1);
    }

    #[tokio::test]
    async fn worker_failure_closes_running_capture_and_vetoes_republication() {
        let open = Arc::new(AtomicBool::new(false));
        let gate = Arc::new(Capture {
            phase: watch::channel(Phase::Starting).0,
            open: open.clone(),
        });
        gate.publish(|| Ok(()), || Ok(())).unwrap();
        let fence = CloseOnDrop(gate.clone());
        assert!(open.load(Ordering::Acquire));
        let worker = tokio::spawn(async move {
            let _fence = fence;
            panic!("injected queue failure");
        });
        assert!(worker.await.unwrap_err().is_panic());
        gate.closed().await;
        assert!(!open.load(Ordering::Acquire));
        assert!(
            gate.publish(
                || -> anyhow::Result<()> { panic!("closed capture republished") },
                || Ok(())
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn failed_ready_queue_keeps_capture_closed() {
        let (queue, ready) = oneshot::channel();
        drop(queue);
        let result =
            publish_after_ready(vec![ready], async { Ok(()) }, || -> anyhow::Result<()> {
                panic!("failed queue published routes")
            })
            .await;
        assert!(result.is_err());
    }
}
