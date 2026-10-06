use super::session::{QueuedData, RequestOwner, XhttpSession};
use crate::session::ManagedSession;
use bytes::Bytes;
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};

pub(super) struct ResponseReader {
    response: Option<h2::client::ResponseFuture>,
    recv: Option<h2::RecvStream>,
    pub(super) session: Arc<XhttpSession>,
    reset: Option<h2::SendStream<QueuedData>>,
    pub(super) permit: Option<RequestOwner>,
    error: Option<Arc<io::Error>>,
}
impl ResponseReader {
    pub(super) fn new(
        response: h2::client::ResponseFuture,
        session: Arc<XhttpSession>,
        reset: Option<h2::SendStream<QueuedData>>,
    ) -> Self {
        Self {
            response: Some(response),
            recv: None,
            session,
            reset,
            permit: None,
            error: None,
        }
    }
    pub(super) fn poll_headers(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = &self.error {
            return Poll::Ready(Err(clone_error(error)));
        }
        if let Some(response) = &mut self.response {
            let response = match Pin::new(response).poll(cx) {
                Poll::Pending if self.session.is_closed() => {
                    let error = Arc::new(self.session.stopped());
                    self.error = Some(error.clone());
                    return Poll::Ready(Err(clone_error(&error)));
                }
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => {
                    let error = Arc::new(self.session.error(error));
                    self.error = Some(error.clone());
                    return Poll::Ready(Err(clone_error(&error)));
                }
                Poll::Ready(Ok(response)) => response,
            };
            self.response = None;
            if response.status() != http::StatusCode::OK {
                let error = Arc::new(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    StatusFailure(response.status().as_u16()),
                ));
                self.error = Some(error.clone());
                return Poll::Ready(Err(clone_error(&error)));
            }
            self.recv = Some(response.into_body());
        }
        Poll::Ready(Ok(()))
    }
    pub(super) fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<Bytes>>> {
        ready!(self.poll_headers(cx))?;
        let recv = self
            .recv
            .as_mut()
            .expect("successful headers supply receive stream");
        match recv.poll_data(cx) {
            Poll::Ready(Some(Ok(data))) => Poll::Ready(Ok(Some(data))),
            Poll::Ready(Some(Err(error))) => Poll::Ready(Err(self.session.error(error))),
            Poll::Ready(None) => match recv.poll_trailers(cx) {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(self.session.error(error))),
                Poll::Pending => Poll::Pending,
            },
            Poll::Pending if self.session.is_closed() => Poll::Ready(Err(self.session.stopped())),
            Poll::Pending => Poll::Pending,
        }
    }
    pub(super) fn release(&mut self, bytes: usize) -> io::Result<()> {
        self.recv
            .as_mut()
            .unwrap()
            .flow_control()
            .release_capacity(bytes)
            .map_err(|error| self.session.error(error))
    }
}
impl Drop for ResponseReader {
    fn drop(&mut self) {
        if let Some(send) = &mut self.reset {
            send.send_reset(h2::Reason::CANCEL);
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("XHTTP peer answered HTTP {0}")]
pub(super) struct StatusFailure(u16);

#[derive(Debug)]
pub(super) struct RetainedError(Arc<io::Error>);

impl std::fmt::Display for RetainedError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), formatter)
    }
}

impl std::error::Error for RetainedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        // io::Error::source skips its immediate custom payload. Retaining an
        // Arc<io::Error> alone therefore loses leaf HTTP/H2/packet error types.
        match self.0.get_ref() {
            Some(cause) => Some(cause),
            None => Some(self.0.as_ref()),
        }
    }
}

pub(super) fn clone_error(error: &Arc<io::Error>) -> io::Error {
    io::Error::new(error.kind(), RetainedError(error.clone()))
}
