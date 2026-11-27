use super::*;
use crate::control::netstack::stream_error;
use crate::relay::RelayError;
use honk_netstack::StreamError;
use std::io::{IoSliceMut, Read, Write};
use std::net::Shutdown;

const DIRECTION_BYTES: usize = 64 << 10;
const SMALL_READ: usize = 4 << 10;
const CALLS: usize = 8;

pub(super) struct Pump {
    pub(super) id: FlowId,
    pub(super) socket: TcpStream,
    pub(super) progress: observation::Progress,
    started: Instant,
    sock_read: bool,
    sock_read_tail: bool,
    sock_write: bool,
    sock_error: bool,
    upload_done: bool,
    remote_eof: bool,
    download_bulk: bool,
    download_blocked: bool,
    download_done: bool,
}

fn client(error: StreamError) -> anyhow::Error {
    RelayError::new(stream_error(error), true).into_anyhow()
}

impl Pump {
    pub(super) fn new(id: FlowId, attach: DirectAttach, now: Instant) -> Self {
        let (socket, progress) = attach.accepted();
        Self {
            id,
            socket,
            progress,
            started: now,
            sock_read: false,
            sock_read_tail: false,
            sock_write: true,
            sock_error: false,
            upload_done: false,
            remote_eof: false,
            download_bulk: false,
            download_blocked: false,
            download_done: false,
        }
    }

    pub(super) fn socket_ready(&mut self, flags: u32) {
        let both = libc::EPOLLERR | libc::EPOLLHUP;
        let tail = flags & (libc::EPOLLRDHUP | both) as u32 != 0;
        self.sock_read |= tail || flags & libc::EPOLLIN as u32 != 0;
        self.sock_read_tail |= tail;
        self.sock_write |= flags & (libc::EPOLLOUT | both) as u32 != 0;
        self.sock_error |= flags & libc::EPOLLERR as u32 != 0;
    }

    pub(super) fn wants_write_epoll(&self) -> bool {
        !self.sock_write && !self.upload_done
    }

    pub(super) fn needs_edge_epoll(&self) -> bool {
        self.download_blocked || self.sock_read_tail || self.download_done
    }

    pub(super) fn needs_epoll(&self) -> bool {
        (!self.download_done && !self.sock_read)
            || self.wants_write_epoll()
            || (self.download_done && !self.sock_error)
    }

    pub(super) fn done(&self) -> bool {
        self.upload_done && self.download_done
    }

    pub(super) fn draining(&self) -> bool {
        self.upload_done || self.download_done
    }

    pub(super) fn stats(&self, now: Instant) -> RelayStats {
        let snapshot = &self.progress.snapshot;
        RelayStats {
            client_to_proxy: snapshot.upload,
            proxy_to_client: snapshot.download,
            total_bytes: snapshot.upload + snapshot.download,
            duration_ms: now.saturating_duration_since(self.started).as_millis() as u64,
        }
    }

    pub(super) fn finish_drain(
        &self,
        stack: &mut Stack,
        now: Instant,
    ) -> anyhow::Result<RelayStats> {
        stack.tcp_shutdown(self.id).map_err(client)?;
        // A full Stack TX ring can prevent readv from surfacing a pending reset.
        if let Some(error) = self.socket.take_error()? {
            return Err(error.into());
        }
        Ok(self.stats(now))
    }

    // Quotas self-schedule. Socket readiness and Stack credit are separate resume edges.
    pub(super) fn drive(
        &mut self,
        stack: &mut Stack,
        now: Instant,
        edge_read: bool,
    ) -> anyhow::Result<bool> {
        let upload = self.upload(stack, now)?;
        let download = self.download(stack, now, edge_read)?;
        // A Stack error can arrive after upload's FIN while download waits on the socket.
        if self.upload_done
            && !self.download_done
            && !self.sock_read
            && let Err(error) = stack.tcp_peek_rx(self.id, 1)
            && error != StreamError::WouldBlock
        {
            return Err(client(error));
        }
        // After forwarding the upstream FIN there is no further read to surface its reset.
        if self.download_done
            && std::mem::take(&mut self.sock_error)
            && let Some(error) = self.socket.take_error()?
        {
            return Err(error.into());
        }
        Ok(upload || download)
    }

    fn upload(&mut self, stack: &mut Stack, now: Instant) -> anyhow::Result<bool> {
        if self.upload_done {
            return Ok(false);
        }
        let mut left = DIRECTION_BYTES;
        for _ in 0..CALLS {
            let (slices, count, eof) = match stack.tcp_peek_rx(self.id, left) {
                Ok(data) => data,
                Err(StreamError::WouldBlock) => return Ok(false),
                Err(error) => return Err(client(error)),
            };
            if count == 0 {
                if eof {
                    self.socket.shutdown(Shutdown::Write)?;
                    self.upload_done = true;
                }
                return Ok(false);
            }
            if !self.sock_write {
                return Ok(false);
            }
            match self.socket.write_vectored(&slices[..count]) {
                Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                Ok(n) => {
                    stack.tcp_consume_rx(self.id, n)?;
                    self.progress.add(true, n, now);
                    left -= n;
                    if left == 0 {
                        break;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.sock_write = false;
                    return Ok(false);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
                Err(error) => return Err(error.into()),
            }
        }
        Ok(true)
    }

    fn download(
        &mut self,
        stack: &mut Stack,
        now: Instant,
        edge_read: bool,
    ) -> anyhow::Result<bool> {
        self.download_blocked = false;
        if self.download_done || !self.sock_read {
            return Ok(false);
        }
        if self.remote_eof {
            return self.shutdown_download(stack);
        }
        // A co-reported FIN or error needs a full drain even on a level-triggered watch.
        let level_read = !edge_read && !self.sock_read_tail;
        let mut left = DIRECTION_BYTES;
        for _ in 0..CALLS {
            let mut offered = 0;
            let fill = |spare: &mut [IoSliceMut<'_>]| {
                if level_read {
                    offered = spare.iter().map(|part| part.len()).sum();
                }
                (&self.socket).read_vectored(spare)
            };
            // Each successful read commits its own prefix before another syscall can see EOF
            // or an error. Small responses only need a single chunk loan.
            let loan = if self.download_bulk {
                stack.tcp_reserve_tx(self.id, left, fill)
            } else {
                stack.tcp_reserve_tx_chunk(self.id, left.min(SMALL_READ), fill)
            };
            match loan {
                Ok(Ok(0)) => return self.shutdown_download(stack),
                Ok(Ok(n)) => {
                    self.progress.add(false, n, now);
                    self.download_bulk |= n >= SMALL_READ;
                    if level_read && n < offered {
                        self.sock_read = false;
                        return Ok(false);
                    }
                    left -= n;
                    if left == 0 {
                        break;
                    }
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.sock_read = false;
                    return Ok(false);
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => (),
                Ok(Err(error)) => return Err(error.into()),
                Err(StreamError::WouldBlock) => {
                    self.download_blocked = true;
                    return Ok(false);
                }
                Err(error) => return Err(client(error)),
            }
        }
        Ok(true)
    }

    fn shutdown_download(&mut self, stack: &mut Stack) -> anyhow::Result<bool> {
        match stack.tcp_shutdown(self.id) {
            Ok(()) => self.download_done = true,
            Err(StreamError::WouldBlock) => {
                self.remote_eof = true;
                self.download_blocked = true;
            }
            Err(error) => return Err(client(error)),
        }
        Ok(false)
    }
}
