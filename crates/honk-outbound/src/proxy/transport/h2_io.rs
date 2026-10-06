use super::AsyncReadWrite;
use bytes::{Buf, Bytes};
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) trait FlushProgress {
    fn writing(&self);
    fn flushed(&self);
}

pub(crate) trait DataProgress {
    fn released(&self);
}

impl<P: DataProgress> DataProgress for Arc<P> {
    fn released(&self) {
        self.as_ref().released();
    }
}

#[derive(Debug)]
pub(crate) struct TrackedIo<P> {
    pub(crate) inner: Box<dyn AsyncReadWrite>,
    pub(crate) progress: Arc<P>,
}

impl<P: FlushProgress> AsyncRead for TrackedIo<P> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<P: FlushProgress> AsyncWrite for TrackedIo<P> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.progress.writing();
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.progress.writing();
        Pin::new(&mut self.inner).poll_write_vectored(cx, bytes)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.inner).poll_flush(cx))?;
        self.progress.flushed();
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// h2 retains this buffer across DATA fragmentation, including later window reductions.
// A physical control-frame flush cannot alone acknowledge queued application data.
#[derive(Debug)]
pub(crate) struct QueuedData<P: DataProgress> {
    pub(crate) bytes: Bytes,
    pub(crate) progress: P,
}

impl<P: DataProgress> Buf for QueuedData<P> {
    fn remaining(&self) -> usize {
        self.bytes.remaining()
    }
    fn chunk(&self) -> &[u8] {
        self.bytes.chunk()
    }
    fn advance(&mut self, count: usize) {
        self.bytes.advance(count);
    }
}

impl<P: DataProgress> Drop for QueuedData<P> {
    fn drop(&mut self) {
        self.progress.released();
    }
}
