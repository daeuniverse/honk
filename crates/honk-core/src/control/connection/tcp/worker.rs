use super::input::{DirectFallback, RemoteAccounting, WorkerRemote};
use super::*;
use crate::control::netstack::local::LocalFlow;
use crate::control::packet_endpoint::DirectCompletion;
use crate::control::task_registry::TASK_BOOKKEEPING;
use crate::group::{ScoreOutcome, ScoreReporter};
use crate::stats::{OutboundKind, StatsManager};
use crate::xdp::worker::direct::{DirectAttach, DirectObserver, DirectOutcome, DirectSnapshot};
use honk_netstack::MemoryReservation;
use honk_outbound::ProxyStream;
use std::future::poll_fn;
use std::io;
use tokio::sync::{OwnedSemaphorePermit, mpsc};

type Admission = (OwnedSemaphorePermit, super::super::ConnectionGuard);

pub(super) struct WorkerTcp<'a> {
    pub(super) completion_credit: Option<MemoryReservation>,
    copy_credit: Option<MemoryReservation>,
    completions: &'a mpsc::UnboundedSender<DirectCompletion>,
    admission: Option<Admission>,
    remote: Option<RemoteAccounting>,
    handed_off: bool,
}

impl<'a> WorkerTcp<'a> {
    pub(super) fn complete_on_worker(
        &mut self,
        job: WorkerDirect,
        credit: MemoryReservation,
    ) -> anyhow::Result<()> {
        let admission = self.admission.take().expect("one worker admission");
        drop(self.copy_credit.take());
        self.completions
            .send(Box::pin(job.finish(admission, credit)))
            .map_err(|_| anyhow::anyhow!("packet Direct completion owner closed"))?;
        self.handed_off = true;
        Ok(())
    }

    pub(super) fn remote<'b>(
        &'b mut self,
        score: Option<&'b ScoreReporter>,
        direct_fallback: Option<DirectFallback<'b>>,
    ) -> WorkerRemote<'b> {
        WorkerRemote {
            accounting: &mut self.remote,
            copy_credit: self
                .copy_credit
                .take()
                .expect("one worker copy reservation"),
            score,
            direct_fallback,
        }
    }

    pub(super) fn release_copy_credit(&mut self) {
        drop(self.copy_credit.take());
    }
}

impl ControlPlaneHandle {
    pub(in crate::control) async fn serve_worker_packet_connection(
        &self,
        stream: FlowIo,
        (completion_credit, copy_credit): (MemoryReservation, MemoryReservation),
        cancel: AbortRegistration,
        completions: mpsc::UnboundedSender<DirectCompletion>,
        admission: (OwnedSemaphorePermit, super::super::ConnectionGuard),
    ) -> anyhow::Result<()> {
        let client = stream.peer_addr();
        let destination = stream.local_addr();
        let local = stream.local().expect("physical packet TCP flow").clone();
        let mut worker = WorkerTcp {
            completion_credit: Some(completion_credit),
            copy_credit: Some(copy_credit),
            completions: &completions,
            admission: Some(admission),
            remote: None,
            handed_off: false,
        };
        let result = std::panic::AssertUnwindSafe(async {
            let stop = Abortable::new(std::future::pending::<()>(), cancel);
            tokio::select! {
                biased;
                _ = stop => None,
                result = self.serve_tcp_input(
                    TcpInput::Packet(stream), client, destination, None, None, Some(&mut worker),
                ) => Some(result),
            }
        })
        .catch_unwind()
        .await;
        worker.release_copy_credit();
        let retired = if worker.handed_off {
            Ok(())
        } else {
            if !matches!(&result, Ok(Some(Ok(())))) {
                local.abort();
            }
            let retired = local.wait().await;
            if let Some(accounting) = &mut worker.remote {
                accounting.publish();
            }
            retired
        };
        match result {
            Ok(result) => result
                .unwrap_or(Ok(()))
                .and_then(|()| retired.map_err(Into::into)),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

pub(super) enum DirectStart {
    Submitted(DirectObserver, MemoryReservation),
    Remote(ProxyStream),
    Closed,
}

pub(super) fn start_direct(
    local: &LocalFlow,
    socket: ProxyStream,
    progress: &relay::RelayProgress,
    observe_live: bool,
    close: Option<&Arc<CloseSignal>>,
) -> io::Result<DirectStart> {
    if close.is_some_and(|signal| signal.cancelled().now_or_never().is_some()) {
        local.abort();
        return Ok(DirectStart::Closed);
    }
    let Some(job_credit) = reserve_job(local, WorkerDirect::finish) else {
        return Ok(DirectStart::Remote(socket));
    };
    let Some(socket_credit) = local.reserve_direct() else {
        return Ok(DirectStart::Remote(socket));
    };
    let socket = match socket.into_tcp_stream() {
        Ok(socket) => socket.into_std()?,
        Err(socket) => return Ok(DirectStart::Remote(socket)),
    };
    let (attach, observer) = DirectAttach::new(socket, progress, socket_credit, observe_live);
    match local.submit_direct(attach) {
        Ok(()) => Ok(DirectStart::Submitted(observer, job_credit)),
        // The occupied request cell already returned the original socket to this observer.
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            Ok(DirectStart::Submitted(observer, job_credit))
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => Ok(DirectStart::Closed),
        Err(error) => Err(error),
    }
}

fn reserve_job<F: Future<Output = ()>>(
    local: &LocalFlow,
    _finish: impl FnOnce(WorkerDirect, Admission, MemoryReservation) -> F,
) -> Option<MemoryReservation> {
    // Includes the boxed future, ready-list node and completion channel cell.
    local.reserve(size_of::<F>() + TASK_BOOKKEEPING)
}

pub(super) struct WorkerDirect {
    pub(super) flow: TcpFlow,
    pub(super) observer: DirectObserver,
    pub(super) close: Option<Arc<CloseSignal>>,
    pub(super) score: Option<ScoreReporter>,
    pub(super) observation: ConnectionObservation,
    #[cfg(feature = "native-api")]
    pub(super) relay_observer: Option<honk_outbound::runtime::flow_observation::FlowObserver>,
    pub(super) stats: Arc<StatsManager>,
    pub(super) outbound: (String, OutboundKind),
    pub(super) endpoints: (SocketAddr, SocketAddr),
}

impl WorkerDirect {
    async fn finish(self, _admission: Admission, _credit: MemoryReservation) {
        let local = self.flow.local().expect("direct worker flow").clone();
        if let Err(panic) = std::panic::AssertUnwindSafe(self.complete(&local))
            .catch_unwind()
            .await
        {
            local.abort();
            let _ = local.wait().await;
            std::panic::resume_unwind(panic);
        }
    }

    async fn complete(mut self, local: &LocalFlow) {
        let close = self.close.take();
        let mut cancelled = std::pin::pin!(wait_for_close(close.as_ref()));
        let mut closing = false;
        let mut observed = DirectSnapshot::default();
        let completion = loop {
            let (update, outcome) = tokio::select! {
                biased;
                () = &mut cancelled, if !closing => {
                    closing = true;
                    local.cancel_direct();
                    continue;
                }
                result = poll_fn(|cx| self.observer.poll_update(cx)) => result,
            };
            self.observe(&observed, &update);
            observed = update;
            match outcome {
                Some(DirectOutcome::Finished(result)) => break RelayCompletion::Relayed(result),
                Some(DirectOutcome::Cancelled) => break RelayCompletion::Closed,
                Some(DirectOutcome::Fallback(socket)) if !update.attached => {
                    if closing {
                        self.stats.record_direct_attach_fallback(false);
                        break RelayCompletion::Closed;
                    }
                    break match self.fallback(local, socket, close.as_ref()) {
                        Ok(copy) => copy.await,
                        Err(error) => RelayCompletion::LocalError(error),
                    };
                }
                Some(DirectOutcome::Fallback(_)) => {
                    break RelayCompletion::LocalError(io::Error::other(
                        "registered Direct socket returned before retirement",
                    ));
                }
                None => {}
            }
        };
        if matches!(completion, RelayCompletion::LocalError(_)) {
            local.abort();
        }
        #[cfg(feature = "native-api")]
        let terminal = completion.terminal();
        let outcome = match completion {
            RelayCompletion::Closed => ScoreOutcome::Cancelled,
            RelayCompletion::LocalError(error) => {
                debug!(%error, "preparing packet Direct relay");
                ScoreOutcome::Rejected
            }
            RelayCompletion::Relayed(Ok(_)) => ScoreOutcome::Success,
            RelayCompletion::Relayed(Err(error)) => {
                let (client, destination) = self.endpoints;
                debug!(%error, %client, %destination, "packet Direct relay ended");
                self.stats.record_error(&self.outbound.0, self.outbound.1);
                tcp_relay_score_outcome(&error)
            }
            RelayCompletion::PrefixFailed(_) => unreachable!("local sniff leaves bytes in Stack"),
        };
        if let Some(reporter) = &self.score {
            reporter.finish(outcome);
        }
        let retired = self
            .flow
            .retire(
                RetireAck {
                    close: None,
                    outbound: None,
                },
                None,
            )
            .await;
        #[cfg(feature = "native-api")]
        {
            let (state, reason) = if retired {
                terminal
            } else {
                TcpTerminal::ConnectionFailed
            }
            .outcome();
            self.observation.finish(state, reason);
        }
        #[cfg(not(feature = "native-api"))]
        let _ = retired;
    }

    fn fallback<'a>(
        &'a mut self,
        local: &LocalFlow,
        socket: std::net::TcpStream,
        close: Option<&'a Arc<CloseSignal>>,
    ) -> io::Result<impl Future<Output = RelayCompletion> + Send + 'a> {
        let direct_fallback = DirectFallback::new(&self.stats);
        let copy_credit = local
            .reserve(relay::REMOTE_COPY_BUFFER_MEMORY)
            .ok_or(io::ErrorKind::OutOfMemory)?;
        #[cfg(test)]
        crate::control::packet_endpoint::worker_copy_tests::observe(&copy_credit);
        let socket = TcpStream::from_std(socket)?;
        let mut progress = self.observer.copy_progress();
        let score = self.score.as_ref();
        progress.first_response =
            self.observation.first_response(score.cloned().map(|score| {
                Arc::new(move || score.first_response()) as Arc<dyn Fn() + Send + Sync>
            }));
        progress.on_transfer = super::accepted_transfer(score, &self.observation);
        let flow = &mut self.flow;
        let endpoints = self.endpoints;
        #[cfg(feature = "native-api")]
        let observer = self.relay_observer.as_ref();
        let copy = async move {
            let mut accounting = None;
            let remote = WorkerRemote {
                accounting: &mut accounting,
                copy_credit,
                score,
                direct_fallback: Some(direct_fallback),
            };
            let relay =
                flow.relay_worker_remote(Box::new(socket), endpoints, progress, close, remote);
            #[cfg(feature = "native-api")]
            let relay = input::observe_relay(observer, relay);
            match std::panic::AssertUnwindSafe(relay).catch_unwind().await {
                Ok(completion) => completion,
                Err(panic) => {
                    let local = flow.local().expect("worker fallback owns a local flow");
                    local.abort();
                    local.close();
                    let _ = local.wait().await;
                    if let Some(accounting) = &mut accounting {
                        accounting.publish();
                    }
                    std::panic::resume_unwind(panic);
                }
            }
        };
        // Only the refused socket pays for the larger copy future and its boxed socket.
        let credit = local
            .reserve(size_of_val(&copy) + size_of::<TcpStream>())
            .ok_or(io::ErrorKind::OutOfMemory)?;
        let copy = Box::pin(copy);
        Ok(async move {
            let _credit = credit;
            copy.await
        })
    }

    fn observe(&self, previous: &DirectSnapshot, update: &DirectSnapshot) {
        let mut upload = update.upload - previous.upload;
        let download = update.download - previous.download;
        let first_upload = update
            .first_upload
            .filter(|_| previous.upload == 0 && upload != 0);
        let mut first_response = update
            .first_response
            .filter(|_| previous.first_response.is_none());
        if let (Some(reply), Some(send)) = (first_response, first_upload)
            && reply < send
        {
            self.report_first_reply(reply);
            first_response = None;
        }
        if let Some(at) = first_upload {
            // A coalesced update must preserve the first accepted send's time.
            if let Some(score) = &self.score {
                score.transfer_at(1, 0, at);
            }
            upload -= 1;
            #[cfg(feature = "native-api")]
            if let Some(flow) = self.observation.flow() {
                flow.accepted_send();
            }
        }
        if let Some(at) = first_response {
            self.report_first_reply(at);
        }
        if let Some(score) = &self.score {
            let report_upload = || {
                if upload != 0 {
                    score.transfer_at(upload, 0, update.last_upload.expect("accepted upload time"));
                }
            };
            let report_download = || {
                if download != 0 {
                    score.transfer_at(
                        0,
                        download,
                        update.last_download.expect("accepted download time"),
                    );
                }
            };
            if update.last_upload <= update.last_download {
                report_upload();
                report_download();
            } else {
                report_download();
                report_upload();
            }
        }
    }

    fn report_first_reply(&self, at: std::time::Instant) {
        if let Some(score) = &self.score {
            score.first_response_at(at);
        }
        self.observation.tcp_first_response();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::netstack::{CAPTURE_MEMORY, capture_realm};
    use crate::control::packet_endpoint::worker_copy_tests::{
        COPY_BYTES, CopyPressure, accept_local_syn,
    };
    use honk_netstack::MemoryBudget;
    use std::task::{Context, Waker};
    use std::time::{Duration, Instant};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    #[tokio::test(flavor = "current_thread")]
    async fn worker_direct_fallback_copy_budget_boundary() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for headroom in [COPY_BYTES - 1, COPY_BYTES] {
                let budget = MemoryBudget::new(CAPTURE_MEMORY);
                let (realm, mut owners) = capture_realm(1280, 1, 2, 1, 1, &budget).unwrap();
                let scope = realm.owner(0).unwrap().clone();
                let owner = owners.pop().unwrap();
                let mut driver = owner.hand_off();
                driver.make_local(1).unwrap();
                scope.open_admission_if(|| true).unwrap();

                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let destination = listener.local_addr().unwrap();
                let flow = accept_local_syn(&mut driver, destination);
                let endpoints = (flow.peer_addr(), destination);
                let local = flow.local().unwrap().clone();
                let dialed = TcpStream::connect(destination).await.unwrap();
                let (mut peer, _) = listener.accept().await.unwrap();
                let progress = relay::RelayProgress {
                    upload: Arc::default(),
                    download: Arc::default(),
                    outbound: None,
                    first_response: None,
                    on_transfer: None,
                };
                let (attach, mut observer) = DirectAttach::new(
                    dialed.into_std().unwrap(),
                    &progress,
                    local.reserve_direct().unwrap(),
                    false,
                );
                attach.reject();
                let (snapshot, outcome) = poll_fn(|cx| observer.poll_update(cx)).await;
                assert!(!snapshot.attached);
                let Some(DirectOutcome::Fallback(socket)) = outcome else {
                    panic!("Direct refusal must return the original socket");
                };
                let mut job = WorkerDirect {
                    flow: TcpFlow::packet(flow, Arc::new(ConnectionTracker::new())),
                    observer,
                    close: None,
                    score: None,
                    observation: ConnectionObservation::begin(
                        None,
                        crate::observe::vocab::Network::Tcp,
                        endpoints.0,
                        endpoints.1,
                    ),
                    #[cfg(feature = "native-api")]
                    relay_observer: None,
                    stats: Arc::new(StatsManager::new()),
                    outbound: ("direct".into(), OutboundKind::Builtin),
                    endpoints,
                };

                // The original socket and observer are already live. The boxed fallback
                // future and Tokio socket get their separate grant after the copy grant.
                let baseline = budget.used();
                let (grant, metadata) = {
                    let pressure = CopyPressure::new(&budget, headroom);
                    let close = CloseSignal::new();
                    let fallback = job.fallback(&local, socket, Some(&close));
                    let grant = pressure.granted();
                    assert_eq!(grant, (headroom == COPY_BYTES).then_some(COPY_BYTES));
                    drop(pressure);
                    let metadata = match fallback {
                        Err(error) => {
                            assert_eq!(headroom, COPY_BYTES - 1);
                            assert_eq!(error.kind(), io::ErrorKind::OutOfMemory);
                            0
                        }
                        Ok(copy) => {
                            assert_eq!(headroom, COPY_BYTES);
                            let metadata = budget.used().checked_sub(baseline + COPY_BYTES).unwrap();
                            assert!(metadata > size_of::<TcpStream>());
                            close.finish(true);
                            assert!(matches!(copy.await, RelayCompletion::Closed));
                            metadata
                        }
                    };
                    (grant, metadata)
                };
                assert_eq!(budget.used(), baseline);
                assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);

                drop((job, local));
                scope.shutdown(true);
                driver.service_closing(&mut Context::from_waker(Waker::noop()), Instant::now());
                assert!(owner.reclaim().await);
                owner.run().await;
                drop((driver, scope, realm));
                assert_eq!(budget.used(), 0);
                eprintln!(
                    "worker_fallback_copy_budget headroom={headroom} grant={grant:?} metadata={metadata} final_used=0"
                );
            }
        })
        .await
        .expect("refused Direct socket and Worker flow must retire and refund");
    }
}
