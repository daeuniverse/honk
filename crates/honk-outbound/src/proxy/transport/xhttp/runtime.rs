use super::preparation::PreparationState;
use super::request::{RequestTemplate, ResolvedMode, sample};
use super::session::connect;
use super::stream::{Flow, FlowPermit, FlushBarriers, XhttpStream};
use super::upload::{
    RequestContext, Upload, UploadLane, UploadRequest, carrier_closed, packet_upload,
    streaming_upload,
};
use super::{MAX_CARRIERS, MAX_REQUESTS, STREAM_WRITE, XhttpPreparation, XhttpSession};
use crate::proxy::{AsyncReadWrite, transport::maybe_tls_wrap};
use crate::runtime::NodeRuntime;
use crate::session::{OpenError, SessionPermit, SessionPool, SessionPoolConfig};
use bytes::Bytes;
use honk_config::node::Node;
use parking_lot::Mutex;
use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    sync::{Notify, Semaphore},
    time::Instant,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    Running,
    Retired,
    ShuttingDown,
}

#[derive(Debug)]
pub(super) struct Lifecycle {
    pub(super) phase: Phase,
    warm_retained: bool,
}

impl Lifecycle {
    pub(super) fn is_retired(&self) -> bool {
        self.phase != Phase::Running
    }
}

#[derive(Debug)]
pub(crate) struct XhttpRuntime {
    pub(crate) pool: Arc<SessionPool<XhttpSession>>,
    // Leave room for uploads: GET-only packet flows cannot consume every request slot.
    flows: Arc<Semaphore>,
    admission: tokio::sync::Mutex<()>,
    pub(super) lifecycle: Mutex<Lifecycle>,
    template: Result<RequestTemplate, crate::SharedError>,
    pub(super) lifecycle_changed: Notify,
}

fn packet_flush_barriers(node: &Node) -> FlushBarriers {
    // Setup + first application flush; Encryption's handshake needs an extra barrier.
    // Keep that extra barrier on resumed 0-RTT to avoid depending on mutable ticket state.
    FlushBarriers {
        remaining: 2 + u8::from(node.vless().is_some_and(|vless| vless.is_encrypted())),
        settled_prefix: 0,
    }
}

impl XhttpRuntime {
    pub(crate) fn new(node: &Node) -> Option<Arc<Self>> {
        if !node.is_xhttp() {
            return None;
        }
        Some(Arc::new(Self {
            pool: Arc::new(SessionPool::new(SessionPoolConfig {
                max_sessions: MAX_CARRIERS,
                max_streams_per_session: MAX_REQUESTS,
                ..SessionPoolConfig::default()
            })),
            flows: Arc::new(Semaphore::new(MAX_REQUESTS)),
            admission: tokio::sync::Mutex::new(()),
            lifecycle: Mutex::new(Lifecycle {
                phase: Phase::Running,
                warm_retained: false,
            }),
            template: RequestTemplate::new(node).map_err(crate::SharedError::new),
            lifecycle_changed: Notify::new(),
        }))
    }

    pub(crate) fn set_dial_admission(&self, admission: crate::runtime::CapturedDialAdmission) {
        let lifecycle = self.lifecycle.lock();
        if !lifecycle.is_retired() {
            self.pool.set_dial_admission(admission);
        }
    }

    pub(crate) fn retire(&self) {
        let mut lifecycle = self.lifecycle.lock();
        if lifecycle.phase == Phase::Running {
            lifecycle.phase = Phase::Retired;
        }
        self.pool.clear_dial_admission();
        self.lifecycle_changed.notify_waiters();
        self.finish_retirement_locked(&lifecycle);
    }

    pub(crate) fn shutdown(&self) {
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.phase = Phase::ShuttingDown;
        self.lifecycle_changed.notify_waiters();
        self.pool.shutdown();
    }

    pub(crate) fn set_warm_retained(&self, retained: bool) {
        let mut lifecycle = self.lifecycle.lock();
        lifecycle.warm_retained = retained;
        if retained || self.flows.available_permits() == MAX_REQUESTS {
            self.pool.set_warm_retained(retained);
        }
    }

    pub(super) fn is_retired(&self) -> bool {
        self.lifecycle.lock().is_retired()
    }

    pub(super) fn template(&self) -> anyhow::Result<&RequestTemplate> {
        self.template
            .as_ref()
            .map_err(|error| anyhow::Error::new(error.clone()))
    }

    pub(super) fn finish_retirement(&self) {
        self.finish_retirement_locked(&self.lifecycle.lock());
    }

    fn finish_retirement_locked(&self, lifecycle: &Lifecycle) {
        if self.flows.available_permits() != MAX_REQUESTS {
            return;
        }
        if lifecycle.is_retired() {
            self.pool.retire();
        } else {
            self.pool.set_warm_retained(lifecycle.warm_retained);
        }
    }

    pub(super) fn dial(
        runtime: Arc<NodeRuntime>,
        tcp: Arc<Mutex<Option<TcpStream>>>,
        timeout: Duration,
    ) -> Pin<Box<impl Future<Output = anyhow::Result<Arc<XhttpSession>>> + Send>> {
        // TLS/ECH setup otherwise copies a large future through each generic pool frame.
        Box::pin(async move {
            let quality = runtime.transport_quality();
            let scope = crate::runtime::capture_dial_scope().physical_setup();
            let feedback = scope.clone();
            let deadline = Instant::now() + timeout * 3;
            let setup = scope.scope(quality.scope(async move {
                let permit = runtime.acquire_carrier_permit()?;
                let tcp = tcp.lock().take();
                let stream = maybe_tls_wrap(&runtime.node, tcp, timeout).await?;
                let stream: Box<dyn AsyncReadWrite> = match permit {
                    Some(permit) => Box::new(crate::proxy::RuntimeOwnedIo {
                        inner: stream,
                        _owner: permit,
                    }),
                    None => stream,
                };
                connect(stream).await
            }));
            tokio::pin!(setup);
            tokio::select! {
                biased;
                result = &mut setup => result,
                _ = tokio::time::sleep_until(deadline) => {
                    // Snapshot before dropping setup removes its physical-admission waiter.
                    if feedback.is_waiting_for_admission() {
                        Err(anyhow::Error::new(crate::proxy::PacketRejection::Capacity))
                    } else {
                        Err(io::Error::new(io::ErrorKind::TimedOut, "XHTTP carrier setup timeout").into())
                    }
                }
            }
        })
    }

    pub(crate) async fn warm(runtime: &Arc<NodeRuntime>, timeout: Duration) -> anyhow::Result<()> {
        let transport = runtime
            .xhttp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no XHTTP runtime"))?;
        let runtime = runtime.clone();
        anyhow::ensure!(!transport.is_retired(), "XHTTP runtime retired");
        transport
            .pool
            .offer(move || Self::dial(runtime, Arc::new(Mutex::new(None)), timeout))
            .await?;
        Ok(())
    }

    pub(super) async fn reserve_pooled(
        &self,
        runtime: &Arc<NodeRuntime>,
        tcp: Arc<Mutex<Option<TcpStream>>>,
        timeout: Duration,
    ) -> anyhow::Result<(Arc<XhttpSession>, SessionPermit<XhttpSession>)> {
        let runtime = runtime.clone();
        let admission = self
            .pool
            .dial_admission()
            .unwrap_or_else(crate::runtime::capture_dial_admission);
        admission
            .scope(self.pool.open_with(
                move || Self::dial(runtime, tcp, timeout),
                |session, permit| std::future::ready(Ok::<_, OpenError>((session, permit))),
            ))
            .await
    }

    pub(super) async fn retired(&self) {
        loop {
            let changed = self.lifecycle_changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.is_retired() {
                return;
            }
            changed.await;
        }
    }

    pub(crate) async fn prepare(
        self: &Arc<Self>,
        runtime: &Arc<NodeRuntime>,
        tcp: Option<TcpStream>,
        timeout: Duration,
    ) -> anyhow::Result<(Box<dyn AsyncReadWrite>, XhttpPreparation)> {
        let state = PreparationState::new(self.clone());
        let preparation = XhttpPreparation::new(state.clone());
        let stream = tokio::select! {
            result = self.open_inner(runtime, tcp, timeout, state) => result?,
            _ = self.retired() => anyhow::bail!("XHTTP runtime retired"),
        };
        Ok((stream, preparation))
    }

    pub(super) async fn open_inner(
        self: &Arc<Self>,
        runtime: &Arc<NodeRuntime>,
        tcp: Option<TcpStream>,
        timeout: Duration,
        preparation: Arc<PreparationState>,
    ) -> anyhow::Result<Box<dyn AsyncReadWrite>> {
        // GET plus its reserved upload lane are one logical admission unit.
        let admission_guard = self.admission.lock().await;
        anyhow::ensure!(!self.is_retired(), "XHTTP runtime retired");
        let flow_permit = self
            .flows
            .clone()
            .try_acquire_owned()
            .map_err(|_| anyhow::Error::new(crate::proxy::PacketRejection::Capacity))?;
        let flow_permit = FlowPermit {
            permit: Some(flow_permit),
            transport: self.clone(),
        };
        let template = self.template()?;
        let session = match template.mode {
            ResolvedMode::StreamOne => String::new(),
            ResolvedMode::PacketUp | ResolvedMode::StreamUp => uuid::Uuid::new_v4().to_string(),
        };
        let tcp = Arc::new(Mutex::new(tcp));
        let context = RequestContext {
            runtime,
            tcp: tcp.clone(),
            timeout,
            preparation: &preparation,
        };
        let (download, upload) = match template.mode {
            ResolvedMode::StreamOne => {
                let request = context
                    .request_with_retry(template.request(&session, None, true, None)?, false, None)
                    .await?;
                Upload::stream_one(request)
            }
            ResolvedMode::StreamUp => {
                let download = context
                    .request_with_retry(template.request(&session, None, false, None)?, true, None)
                    .await?;
                let download = Upload::download(download);
                let upload = context
                    .request_with_retry(template.request(&session, None, true, None)?, false, None)
                    .await?;
                (
                    download,
                    Upload::Streaming(UploadRequest::from_request(upload)),
                )
            }
            ResolvedMode::PacketUp => {
                let download = context
                    .request_with_retry(template.request(&session, None, false, None)?, true, None)
                    .await?;
                let download = Upload::download(download);
                // Reserve alongside GET so one-request peers cannot strand the upload.
                let (session, permit) = preparation.reserve(runtime, tcp.clone(), timeout).await?;
                (download, Upload::Packet(UploadLane::new(session, permit)))
            }
        };
        anyhow::ensure!(!self.is_retired(), "XHTTP runtime retired");
        drop(admission_guard);
        let limit = match template.mode {
            ResolvedMode::PacketUp => sample(template.post_bytes) as usize,
            ResolvedMode::StreamUp | ResolvedMode::StreamOne => STREAM_WRITE,
        };
        let flow = Flow::new(limit);
        let driver_flow = flow.clone();
        let runtime_owner = runtime.clone();
        // Unpublished runtimes have no pool-bound owner to supply replacement admission.
        let admission = crate::runtime::capture_dial_admission();
        let download_session = download.session.clone();
        let driver = tokio::spawn(admission.scope(async move {
            let upload = async {
                match upload {
                    Upload::Streaming(upload) => {
                        streaming_upload(upload, driver_flow.clone()).await
                    }
                    Upload::Packet(lane) => {
                        packet_upload(
                            runtime_owner,
                            tcp,
                            timeout,
                            session,
                            driver_flow.clone(),
                            lane,
                            preparation,
                        )
                        .await
                    }
                }
            };
            let result = tokio::select! {
                result = upload => result,
                error = carrier_closed(download_session) => Err(error),
            };
            if let Err(error) = result {
                driver_flow.fail(error);
            }
        }));
        Ok(Box::new(XhttpStream {
            download,
            flow,
            packet_flush_barriers: (template.mode == ResolvedMode::PacketUp)
                .then(|| packet_flush_barriers(&runtime.node)),
            driver: driver.abort_handle(),
            _runtime: runtime.clone(),
            _flow_permit: flow_permit,
            read_result: None,
            payload: Bytes::new(),
        }))
    }
}

impl Drop for XhttpRuntime {
    fn drop(&mut self) {
        self.pool.shutdown();
    }
}
