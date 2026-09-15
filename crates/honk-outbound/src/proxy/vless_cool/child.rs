use super::codec::*;
use super::*;

pub(super) type IoFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
pub(super) type ReserveFuture = Pin<
    Box<
        dyn Future<Output = Result<mpsc::OwnedPermit<WriterCommand>, mpsc::error::SendError<()>>>
            + Send,
    >,
>;

pub(super) enum StreamOperation {
    Reserve(ReserveFuture),
    Flush(IoFuture),
    Shutdown(IoFuture),
}

pub(crate) struct VlessCoolStream {
    session: Arc<VlessCoolSession>,
    id: u16,
    writer: CarrierWriter,
    rx: mpsc::Receiver<QueuedPayload>,
    current: Option<QueuedPayload>,
    failure: Arc<Mutex<Option<Failure>>>,
    ended: Arc<AtomicBool>,
    pub(super) operation: Option<StreamOperation>,
    closed: bool,
    _permit: SessionPermit<VlessCoolSession>,
}

impl std::fmt::Debug for VlessCoolStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessCoolStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl VlessCoolStream {
    fn poll_operation(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(operation) = self.operation.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let result = match operation {
            StreamOperation::Reserve(_) => unreachable!("write reserves are polled by poll_write"),
            StreamOperation::Flush(future) | StreamOperation::Shutdown(future) => {
                match future.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                }
            }
        };
        self.operation = None;
        Poll::Ready(result)
    }
    fn terminal_error(&self) -> Option<io::Error> {
        self.failure.lock().as_ref().map(Failure::io)
    }
}

impl AsyncRead for VlessCoolStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.current.is_some() {
            let empty = {
                let current = self.current.as_mut().expect("current payload exists");
                let count = output.remaining().min(current.payload.len());
                output.put_slice(&current.payload[..count]);
                current.payload.advance(count);
                current.payload.is_empty()
            };
            if empty {
                self.current = None;
            }
            return Poll::Ready(Ok(()));
        }
        match self.rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(data)) => {
                self.current = Some(data);
                self.poll_read(cx, output)
            }
            Poll::Ready(None) => self.failure.lock().as_ref().map_or_else(
                || Poll::Ready(Ok(())),
                |failure| Poll::Ready(Err(failure.io())),
            ),
        }
    }
}

impl AsyncWrite for VlessCoolStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || self.ended.load(Ordering::Acquire) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let shutdown_pending = matches!(self.operation, Some(StreamOperation::Shutdown(_)));
        if self.operation.is_none() {
            if let Some(error) = self.terminal_error() {
                return Poll::Ready(Err(error));
            }
            self.operation = Some(StreamOperation::Reserve(Box::pin(
                self.writer.tx.clone().reserve_owned(),
            )));
        }
        if let Some(StreamOperation::Reserve(reserve)) = self.operation.as_mut() {
            let permit = match reserve.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(permit)) => permit,
                Poll::Ready(Err(_)) => {
                    self.operation = None;
                    return Poll::Ready(Err(self.terminal_error().unwrap_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "Mux.Cool carrier writer closed")
                    })));
                }
            };
            self.operation = None;
            if self.closed || self.ended.load(Ordering::Acquire) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
            if let Some(error) = self.terminal_error() {
                return Poll::Ready(Err(error));
            }
            let length = data.len().min(MAX_TCP_CHUNK);
            let frame = match keep_tcp_frame(self.id, &data[..length]) {
                Ok(frame) => frame,
                Err(error) => return Poll::Ready(Err(error)),
            };
            let (done, wait) = oneshot::channel();
            drop(wait);
            let _sender = permit.send(WriterCommand {
                frame,
                flush: false,
                done,
            });
            return Poll::Ready(Ok(length));
        }
        match self.poll_operation(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) if shutdown_pending => {
                self.closed = true;
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
            Poll::Ready(Ok(())) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.operation, Some(StreamOperation::Reserve(_))) {
            self.operation = None;
        }
        if self.operation.is_none() {
            if self.ended.load(Ordering::Acquire) {
                return Poll::Ready(Ok(()));
            }
            if let Some(error) = self.terminal_error() {
                return Poll::Ready(Err(error));
            }
            let writer = self.writer.clone();
            self.operation = Some(StreamOperation::Flush(Box::pin(async move {
                writer.flush().await
            })));
        }
        let shutdown_pending = matches!(self.operation, Some(StreamOperation::Shutdown(_)));
        match self.poll_operation(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                if shutdown_pending {
                    self.closed = true;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed || self.ended.load(Ordering::Acquire) {
            self.operation = None;
            self.closed = true;
            return Poll::Ready(Ok(()));
        }
        if matches!(self.operation, Some(StreamOperation::Reserve(_))) {
            self.operation = None;
        }
        loop {
            if self.operation.is_none() {
                let writer = self.writer.clone();
                let session = Arc::clone(&self.session);
                let id = self.id;
                self.operation = Some(StreamOperation::Shutdown(Box::pin(async move {
                    let result = writer
                        .send(end_frame(id), true)
                        .await
                        .map_err(|error| error.failure.io());
                    session.remove_child(id);
                    result
                })));
            }
            let shutdown_pending = matches!(self.operation, Some(StreamOperation::Shutdown(_)));
            match self.poll_operation(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(())) if !shutdown_pending => continue,
                Poll::Ready(Ok(())) => {
                    self.closed = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(error)) => {
                    self.closed = true;
                    return Poll::Ready(Err(error));
                }
            }
        }
    }
}

impl Drop for VlessCoolStream {
    fn drop(&mut self) {
        self.session.remove_child(self.id);
        if !self.closed && !self.ended.load(Ordering::Acquire) && self.failure.lock().is_none() {
            let _ = self.session.schedule_end(self.id);
        }
    }
}

pub(super) async fn open_tcp(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    target: SocketAddr,
    target_domain: Option<&str>,
) -> Result<VlessCoolStream, OpenError> {
    let frame = new_tcp_frame(1, target, target_domain)
        .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?;
    let id = session.allocate_id()?;
    let frame = if id == 1 {
        frame
    } else {
        new_tcp_frame(id, target, target_domain)
            .map_err(|error| OpenError::Refused(anyhow::Error::new(error)))?
    };
    let (tx, rx) = mpsc::channel(TCP_QUEUE_CAPACITY);
    let failure = Arc::new(Mutex::new(None));
    let ended = Arc::new(AtomicBool::new(false));
    session
        .insert_child(
            id,
            ChildSink::Tcp {
                tx,
                failure: Arc::clone(&failure),
                ended: Arc::clone(&ended),
            },
        )
        .map_err(|error| OpenError::Session(anyhow::Error::new(error)))?;
    let mut cancellation = ChildCancellationGuard::new(&session, id);
    if let Err(error) = session.writer.send(frame, true).await {
        session.fail_child(id, error.failure.clone());
        cancellation.disarm();
        return Err(if error.committed {
            OpenError::Refused(anyhow::Error::new(error.failure.io()))
        } else {
            OpenError::Session(anyhow::Error::new(error.failure.io()))
        });
    }
    cancellation.disarm();
    Ok(VlessCoolStream {
        writer: session.writer.clone(),
        session,
        id,
        rx,
        current: None,
        failure,
        ended,
        operation: None,
        closed: false,
        _permit: permit,
    })
}

pub(super) struct UdpWriteState {
    started: bool,
    poisoned: bool,
}
/// Cancellation before queue admission is invisible and retryable; after
/// admission the wire result is ambiguous, so the logical child is poisoned.
struct UdpSendCancellationGuard<'a> {
    session: &'a Arc<VlessCoolSession>,
    id: u16,
    state: &'a mut UdpWriteState,
    admitted: &'a AtomicBool,
    first: bool,
    armed: bool,
}

impl<'a> UdpSendCancellationGuard<'a> {
    fn new(
        session: &'a Arc<VlessCoolSession>,
        id: u16,
        state: &'a mut UdpWriteState,
        admitted: &'a AtomicBool,
        first: bool,
    ) -> Self {
        state.started = true;
        state.poisoned = true;
        Self {
            session,
            id,
            state,
            admitted,
            first,
            armed: true,
        }
    }

    fn complete(mut self) {
        self.state.poisoned = false;
        self.armed = false;
    }
}

impl Drop for UdpSendCancellationGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if self.admitted.load(Ordering::Acquire) {
            self.session
                .fail_child(self.id, Failure::source_post_admission_cancel());
            let _ = self.session.schedule_end(self.id);
            return;
        }
        self.state.poisoned = false;
        if self.first {
            self.state.started = false;
        }
    }
}

struct UdpReadState {
    rx: mpsc::Receiver<Datagram>,
    pending: Option<Datagram>,
}

/// One concrete XUDP logical child with a single receive owner and serialized sends.
pub struct VlessXudpTransport {
    pub(super) session: Arc<VlessCoolSession>,
    pub(super) id: u16,
    writer: CarrierWriter,
    pub(super) write: tokio::sync::Mutex<UdpWriteState>,
    read: tokio::sync::Mutex<UdpReadState>,
    failure: Arc<Mutex<Option<Failure>>>,
    ended: Arc<AtomicBool>,
    target: SocketAddr,
    target_domain: Option<Arc<str>>,
    destination: Arc<Mutex<Option<UdpDestination>>>,
    global_id: [u8; 8],
    _permit: SessionPermit<VlessCoolSession>,
}

impl std::fmt::Debug for VlessXudpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VlessXudpTransport")
            .field("id", &self.id)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

impl VlessXudpTransport {
    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        self.send_to(self.target, self.target_domain.as_deref(), payload, None)
            .await
    }

    /// Whether a serialized source sender may retry after an interrupted send.
    pub async fn source_send_usable(&self) -> bool {
        let state = self.write.lock().await;
        !state.poisoned && self.failure.lock().is_none() && !self.ended.load(Ordering::Acquire)
    }

    /// Send to a view's actual target. The first queue-admitted datagram binds
    /// metadata-less replies; a cancelled pre-admission attempt binds nothing.
    /// The optional marker becomes true only when the carrier writer owns the command.
    pub async fn send_to(
        &self,
        target: SocketAddr,
        target_domain: Option<&str>,
        payload: &[u8],
        admission: Option<&AtomicBool>,
    ) -> io::Result<()> {
        let mut state = self.write.lock().await;
        if self.ended.load(Ordering::Acquire) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if state.poisoned {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XUDP transport is closed after an interrupted send",
            ));
        }
        if let Some(failure) = self.failure.lock().as_ref() {
            return Err(failure.io());
        }
        let first = !state.started;
        let frame = udp_frame(
            self.id,
            first,
            target,
            target_domain,
            self.global_id,
            payload,
        )?;
        let local_admitted = AtomicBool::new(false);
        let admitted = admission.unwrap_or(&local_admitted);
        let cancellation =
            UdpSendCancellationGuard::new(&self.session, self.id, &mut state, admitted, first);
        let result = self
            .writer
            .send_with_admission(frame, true, admitted, || {
                if first {
                    *self.destination.lock() = Some(UdpDestination {
                        peer: target,
                        target_domain: target_domain.map(Arc::<str>::from),
                    });
                }
            })
            .await;
        match result {
            Ok(()) => {
                cancellation.complete();
                Ok(())
            }
            Err(error) => {
                let error = error.failure.io();
                drop(cancellation);
                Err(error)
            }
        }
    }
}

impl Drop for VlessXudpTransport {
    fn drop(&mut self) {
        self.session.remove_child(self.id);
        let Ok(state) = self.write.try_lock() else {
            return;
        };
        if state.started
            && !state.poisoned
            && !self.ended.load(Ordering::Acquire)
            && self.failure.lock().is_none()
        {
            let _ = self.session.schedule_end(self.id);
        }
    }
}

#[async_trait]
impl PacketTransport for VlessXudpTransport {
    fn relay_addr(&self) -> SocketAddr {
        self.target
    }
    fn allows_full_cone_replies(&self) -> bool {
        true
    }

    async fn send_packet(&self, data: &[u8]) -> io::Result<()> {
        self.send(data).await
    }

    async fn send_packet_confirmed(&self, data: &[u8]) -> io::Result<()> {
        self.send(data).await
    }

    async fn recv_packet(&self, output: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut reader = self.read.lock().await;
        loop {
            if let Some(packet) = reader.pending.as_ref() {
                if packet.payload.len() > output.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "XUDP datagram exceeds receive buffer",
                    ));
                }
                let packet = reader.pending.take().expect("pending packet exists");
                output[..packet.payload.len()].copy_from_slice(&packet.payload);
                return Ok((packet.payload.len(), packet.peer));
            }
            match reader.rx.recv().await {
                Some(packet) => reader.pending = Some(packet),
                None => {
                    return Err(self.failure.lock().as_ref().map_or_else(
                        || {
                            io::Error::new(
                                io::ErrorKind::ConnectionAborted,
                                "XUDP logical connection closed",
                            )
                        },
                        Failure::io,
                    ));
                }
            }
        }
    }
}

async fn open_udp_with_id(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    id: u16,
    target: SocketAddr,
    target_domain: Option<&str>,
    global_id: [u8; 8],
) -> Result<Arc<VlessXudpTransport>, OpenError> {
    if global_id == [0; 8] && target_domain.is_some_and(|domain| domain.len() > u8::MAX as usize) {
        return Err(OpenError::Refused(anyhow::Error::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Mux.Cool target domain exceeds 255 bytes",
        ))));
    }
    let target_domain = target_domain.map(Arc::<str>::from);
    let (tx, rx) = mpsc::channel(UDP_QUEUE_CAPACITY);
    let failure = Arc::new(Mutex::new(None));
    let ended = Arc::new(AtomicBool::new(false));
    let destination = Arc::new(Mutex::new(None));
    session
        .insert_child(
            id,
            ChildSink::Udp {
                tx,
                failure: Arc::clone(&failure),
                ended: Arc::clone(&ended),
                destination: Arc::clone(&destination),
            },
        )
        .map_err(|error| OpenError::Session(anyhow::Error::new(error)))?;
    Ok(Arc::new(VlessXudpTransport {
        writer: session.writer.clone(),
        session,
        id,
        write: tokio::sync::Mutex::new(UdpWriteState {
            started: false,
            poisoned: false,
        }),
        read: tokio::sync::Mutex::new(UdpReadState { rx, pending: None }),
        failure,
        ended,
        target,
        target_domain,
        destination,
        global_id,
        _permit: permit,
    }))
}

pub(crate) async fn open_xudp(
    session: Arc<VlessCoolSession>,
    permit: SessionPermit<VlessCoolSession>,
    target: SocketAddr,
    target_domain: Option<&str>,
    global_id: [u8; 8],
) -> Result<Arc<VlessXudpTransport>, OpenError> {
    let id = session.allocate_id()?;
    open_udp_with_id(session, permit, id, target, target_domain, global_id).await
}

pub(crate) async fn connect_single_xudp(
    stream: Box<dyn AsyncReadWrite>,
    target: SocketAddr,
    target_domain: Option<&str>,
    global_id: [u8; 8],
) -> anyhow::Result<Arc<VlessXudpTransport>> {
    let session = connect(stream, 1);
    let permit = session
        .try_reserve()
        .ok_or_else(|| anyhow::anyhow!("Single XUDP carrier has no capacity"))?;
    open_udp_with_id(session, permit, 0, target, target_domain, global_id)
        .await
        .map_err(|error| match error {
            OpenError::Session(error) | OpenError::Refused(error) | OpenError::Draining(error) => {
                error
            }
        })
}
