use super::preparation::PreparationState;
use super::request::sample;
use super::response::{ResponseReader, clone_error};
use super::session::{QueueProgress, QueuedData, Request, RequestOwner};
use super::stream::Flow;
use super::{MAX_PIPELINE, XhttpSession};
use crate::runtime::NodeRuntime;
use crate::session::{ManagedSession, OpenError, SessionPermit};
use bytes::Bytes;
use futures_util::{StreamExt, stream::FuturesUnordered};
use parking_lot::Mutex;
use std::{
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{net::TcpStream, sync::Semaphore, time::Instant};

pub(super) struct UploadLane {
    session: Arc<XhttpSession>,
    _permit: SessionPermit<XhttpSession>,
    available: Arc<Semaphore>,
}

impl UploadLane {
    pub(super) fn new(
        session: Arc<XhttpSession>,
        permit: SessionPermit<XhttpSession>,
    ) -> Arc<Self> {
        Arc::new(Self {
            session,
            _permit: permit,
            available: Arc::new(Semaphore::new(1)),
        })
    }
}

pub(super) enum Upload {
    StreamOne(UploadRequest),
    StreamUp(UploadRequest),
    Packet(Arc<UploadLane>),
}

impl Upload {
    pub(super) fn stream_one(request: Request) -> (ResponseReader, Self) {
        let Request {
            response,
            send,
            permit,
            session,
        } = request;
        let reader = ResponseReader::new(response, session.clone(), None);
        (
            reader,
            Self::StreamOne(UploadRequest::new(send, permit, session, None)),
        )
    }
    pub(super) fn stream_up(download: ResponseReader, upload: Request) -> (ResponseReader, Self) {
        (
            download,
            Self::StreamUp(UploadRequest::from_request(upload)),
        )
    }
    pub(super) fn packet(
        download: ResponseReader,
        lane: Arc<UploadLane>,
    ) -> (ResponseReader, Self) {
        (download, Self::Packet(lane))
    }
    pub(super) fn download(request: Request) -> ResponseReader {
        let mut reader = ResponseReader::new(request.response, request.session, Some(request.send));
        reader.permit = Some(request.permit);
        reader
    }
}

pub(super) struct UploadRequest {
    pub(super) send: h2::SendStream<QueuedData>,
    pub(super) _permit: RequestOwner,
    pub(super) session: Arc<XhttpSession>,
    pub(super) response: Option<h2::client::ResponseFuture>,
    pub(super) pending: Arc<AtomicUsize>,
}
impl UploadRequest {
    pub(super) fn new(
        send: h2::SendStream<QueuedData>,
        permit: RequestOwner,
        session: Arc<XhttpSession>,
        response: Option<h2::client::ResponseFuture>,
    ) -> Self {
        Self {
            send,
            _permit: permit,
            session,
            response,
            pending: Arc::new(AtomicUsize::new(0)),
        }
    }
    fn from_request(request: Request) -> Self {
        Self::new(
            request.send,
            request.permit,
            request.session,
            Some(request.response),
        )
    }
}
impl Drop for UploadRequest {
    fn drop(&mut self) {
        self.send.send_reset(h2::Reason::CANCEL);
    }
}
pub(super) async fn take_batch(
    flow: &Flow,
    delay: Duration,
    last: Instant,
) -> io::Result<Option<Bytes>> {
    let mut deadline = None;
    loop {
        let notified = flow.changed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let (has_data, immediate, shutdown) = {
            let state = flow.state.lock();
            if let Some(error) = &state.error {
                return Err(clone_error(error));
            }
            (
                !state.bytes.is_empty(),
                state.flush_to > state.flushed || state.bytes.len() == flow.limit,
                state.shutdown,
            )
        };
        if has_data {
            if !immediate && !shutdown && !delay.is_zero() {
                let deadline = *deadline.get_or_insert_with(|| Instant::now() + delay);
                tokio::select! { _ = &mut notified => { continue; }, _ = tokio::time::sleep_until(deadline) => {} }
            }
            let next = last + delay;
            if next > Instant::now() {
                tokio::time::sleep_until(next).await;
            }
            let bytes = flow.state.lock().bytes.split().freeze();
            flow.write.wake();
            return Ok(Some(bytes));
        }
        if shutdown {
            return Ok(None);
        }
        notified.await;
    }
}

pub(super) async fn send_body(
    upload: &mut UploadRequest,
    bytes: Bytes,
    end: bool,
) -> io::Result<()> {
    let pending = upload.pending.clone();
    pending.fetch_add(1, Ordering::AcqRel);
    upload
        .session
        .progress
        .flushed
        .store(false, Ordering::Release);
    upload
        .send
        .send_data(
            QueuedData {
                bytes,
                progress: QueueProgress {
                    pending: pending.clone(),
                    io: upload.session.progress.clone(),
                },
            },
            end,
        )
        .map_err(|error| upload.session.error(error))?;
    loop {
        let changed = upload.session.progress.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        // poll_reset installs a request-owned wakeup independent of the connection driver.
        let reset = poll_fn(|cx| match upload.send.poll_reset(cx) {
            Poll::Ready(Ok(reason)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("XHTTP request reset: {reason:?}"),
            ))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(upload.session.error(error))),
            Poll::Pending
                if pending.load(Ordering::Acquire) == 0
                    && upload.session.progress.flushed.load(Ordering::Acquire)
                    && !upload.session.is_failed_terminal() =>
            {
                Poll::Ready(Ok(()))
            }
            Poll::Pending if upload.session.is_closed() => {
                Poll::Ready(Err(upload.session.stopped()))
            }
            Poll::Pending => Poll::Pending,
        });
        tokio::pin!(reset);
        tokio::select! { result = &mut reset => return result, _ = changed => {} }
    }
}

pub(super) async fn carrier_closed(session: Arc<XhttpSession>) -> io::Error {
    loop {
        let changed = session.progress.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        // A clean GOAWAY completion does not invalidate buffered GET EOF or
        // uploads already using another carrier. Explicit shutdown still wakes
        // this observer and publishes the ordinary Closed state.
        if session.is_failed_terminal() {
            return session.stopped();
        }
        changed.await;
    }
}

pub(super) async fn drain_response(
    response: h2::client::ResponseFuture,
    session: Arc<XhttpSession>,
) -> io::Result<()> {
    let mut reader = ResponseReader::new(response, session, None);
    while let Some(bytes) = poll_fn(|cx| reader.poll_data(cx)).await? {
        reader.release(bytes.len())?;
    }
    Ok(())
}

pub(super) async fn streaming_upload(mut upload: UploadRequest, flow: Arc<Flow>) -> io::Result<()> {
    let response = upload.response.take();
    let session = upload.session.clone();
    let send = async {
        loop {
            match take_batch(&flow, Duration::ZERO, Instant::now()).await? {
                Some(bytes) => {
                    let count = bytes.len() as u64;
                    send_body(&mut upload, bytes, false).await?;
                    flow.sent(count, false);
                }
                None => {
                    send_body(&mut upload, Bytes::new(), true).await?;
                    break;
                }
            }
        }
        Ok::<_, io::Error>(())
    };
    if let Some(response) = response {
        let drain = drain_response(response, session);
        tokio::pin!(send, drain);
        let drained = tokio::select! {
            biased;
            result = &mut drain => {
                result?;
                send.await?;
                true
            }
            result = &mut send => {
                result?;
                false
            }
        };
        flow.sent(0, true);
        if !drained {
            drain.await?;
        }
    } else {
        send.await?;
        flow.sent(0, true);
    }
    // Keep the stream-one upload permit until the logical flow drops.
    std::future::pending().await
}

pub(super) async fn packet_upload(
    runtime: Arc<NodeRuntime>,
    tcp: Arc<Mutex<Option<TcpStream>>>,
    timeout: Duration,
    session: String,
    flow: Arc<Flow>,
    first_upload: Arc<UploadLane>,
    preparation: Arc<PreparationState>,
) -> io::Result<()> {
    let transport = runtime
        .xhttp
        .as_ref()
        .expect("packet-up requires its XHTTP runtime");
    let template = transport.template().map_err(shared_io_error)?;
    let mut responses = Responses::new();
    let mut lane = first_upload;
    let mut seq = 0;
    let mut last = Instant::now() - Duration::from_millis(template.post_interval.max as u64);
    loop {
        while responses.len() >= MAX_PIPELINE {
            responses
                .next()
                .await
                .expect("bounded pipeline is nonempty")?;
        }
        let batch = take_batch(
            &flow,
            Duration::from_millis(sample(template.post_interval) as u64),
            last,
        );
        let bytes = drive_with(&mut responses, batch).await?;
        let Some(bytes) = bytes else {
            while let Some(result) = responses.next().await {
                result?;
            }
            flow.sent(0, true);
            return Ok(());
        };
        let count = bytes.len() as u64;
        let request = template
            .request(&session, Some(seq), true, Some(bytes.len()))
            .map_err(shared_io_error)?;
        let context = RequestContext {
            runtime: &runtime,
            tcp: tcp.clone(),
            timeout,
            preparation: &preparation,
        };
        let request = drive_with(&mut responses, async {
            context
                .request_with_retry(request, false, Some(&mut lane))
                .await
                .map_err(shared_io_error)
        })
        .await?;
        last = Instant::now();
        seq += 1;
        let mut upload = UploadRequest::from_request(request);
        let response = upload.response.take().unwrap();
        let response_session = upload.session.clone();
        // A response is drained concurrently while this body is still blocked by flow control.
        // The next POST is admitted after physical body flush, NOT after response completion.
        let mut drain = Box::pin(drain_response(response, response_session));
        let drained = drive_with(&mut responses, async {
            let body = send_body(&mut upload, bytes, true);
            tokio::pin!(body);
            let mut drained = false;
            loop {
                tokio::select! {
                    biased;
                    result = &mut drain, if !drained => { result?; drained = true; }
                    result = &mut body => { result?; return Ok(drained); }
                }
            }
        })
        .await?;
        flow.sent(count, false);
        if !drained {
            // Retain send/reset ownership and the request permit through response drain.
            responses.push(Box::pin(async move {
                let result = drain.await;
                drop(upload);
                result
            }));
        }
    }
}

type Responses = FuturesUnordered<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>>;

async fn drive_with<T>(
    responses: &mut Responses,
    future: impl Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::pin!(future);
    loop {
        tokio::select! {
            biased;
            result = responses.next(), if !responses.is_empty() => { result.unwrap()?; }
            result = &mut future => return result,
        }
    }
}

fn shared_io_error(error: anyhow::Error) -> io::Error {
    io::Error::other(crate::SharedError::new(error))
}

pub(super) struct RequestContext<'a> {
    pub(super) runtime: &'a Arc<NodeRuntime>,
    pub(super) tcp: Arc<Mutex<Option<TcpStream>>>,
    pub(super) timeout: Duration,
    pub(super) preparation: &'a Arc<PreparationState>,
}

impl RequestContext<'_> {
    async fn reserve(&self) -> anyhow::Result<(Arc<XhttpSession>, SessionPermit<XhttpSession>)> {
        self.preparation
            .reserve(self.runtime, self.tcp.clone(), self.timeout)
            .await
    }
    async fn reserve_request(
        &self,
        lane: Option<&mut Arc<UploadLane>>,
    ) -> anyhow::Result<(Arc<XhttpSession>, RequestOwner)> {
        let Some(lane) = lane else {
            let (session, permit) = self.reserve().await?;
            return Ok((session, RequestOwner::Pool { _permit: permit }));
        };
        if !lane.session.reserved_lane_usable() {
            let (session, permit) = self.reserve().await?;
            *lane = UploadLane::new(session, permit);
        }
        let owner_lane = lane.clone();
        // Race reservations, never HEADERS: losing admission has no bytes to replay.
        tokio::select! {
            biased;
            permit = owner_lane.available.clone().acquire_owned() => {
                Ok((owner_lane.session.clone(), RequestOwner::Lane { _lane: owner_lane, _use: permit.expect("an owned upload lane is never closed") }))
            }
            extra = self.reserve() => {
                let (session, permit) = extra?;
                Ok((session, RequestOwner::Pool { _permit: permit }))
            }
        }
    }
    pub(super) async fn request_with_retry(
        &self,
        request: http::Request<()>,
        end: bool,
        mut lane: Option<&mut Arc<UploadLane>>,
    ) -> anyhow::Result<Request> {
        let mut request = Some(request);
        let mut last_error = None;
        for _ in 0..2 {
            let (session, owner) = self.reserve_request(lane.as_deref_mut()).await?;
            match session.clone().request(owner, &mut request, end).await {
                Ok(request) => return Ok(request),
                Err(OpenError::Draining(error)) => {
                    last_error = Some(error);
                    session.begin_drain();
                }
                Err(OpenError::Session(error) | OpenError::Refused(error)) => return Err(error),
            }
        }
        Err(last_error.expect("uncommitted request attempts retain their cause"))
    }
}
