use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use crate::QUEUE_NUM;
use crate::netlink;
use crate::queue::QueueSocket;

pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;
pub(crate) const NFQA_MSG_VERDICT: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_MARK: u16 = 3;

#[derive(Debug, thiserror::Error)]
pub enum VerdictError {
    #[error("packet already has a verdict")]
    AlreadyCommitted,
    #[error("verdict send failed: {0}")]
    Io(#[from] io::Error),
}

pub struct VerdictGuard {
    socket: Arc<QueueSocket>,
    packet_id: u32,
    committed: bool,
    tracker: Arc<GuardTracker>,
}

impl VerdictGuard {
    pub(crate) fn new(
        socket: Arc<QueueSocket>,
        packet_id: u32,
        tracker: Arc<GuardTracker>,
    ) -> Self {
        tracker.acquire();
        Self {
            socket,
            packet_id,
            committed: false,
            tracker,
        }
    }

    pub fn accept(&mut self, mark: u32) -> Result<(), VerdictError> {
        self.commit(NF_ACCEPT, Some(mark))
    }

    pub fn drop_packet(&mut self) -> Result<(), VerdictError> {
        self.commit(NF_DROP, None)
    }

    fn commit(&mut self, verdict: u32, mark: Option<u32>) -> Result<(), VerdictError> {
        if self.committed {
            return Err(VerdictError::AlreadyCommitted);
        }
        // A failed send is fatal, so Drop must not issue a different second decision.
        self.committed = true;
        self.socket
            .send_verdict(self.packet_id, verdict, mark)
            .map_err(VerdictError::Io)
    }
}

impl Drop for VerdictGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.committed = true;
            let _ = self.socket.send_verdict(self.packet_id, NF_DROP, None);
        }
        self.tracker.release();
    }
}

pub(crate) struct GuardTracker {
    count: AtomicUsize,
    peak: AtomicUsize,
    wait_lock: Mutex<()>,
    drained: Condvar,
}

impl GuardTracker {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            count: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            wait_lock: Mutex::new(()),
            drained: Condvar::new(),
        })
    }

    fn acquire(&self) {
        let count = self.count.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(count, Ordering::Relaxed);
    }

    fn release(&self) {
        if self.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _waiter = self
                .wait_lock
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            self.drained.notify_all();
        }
    }

    pub(crate) fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub(crate) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub(crate) fn wait_until_drained(&self) {
        let mut waiter = self
            .wait_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        while self.count.load(Ordering::Acquire) != 0 {
            waiter = self
                .drained
                .wait(waiter)
                .unwrap_or_else(|error| error.into_inner());
        }
    }
}

pub(crate) fn build_verdict_message(
    packet_id: u32,
    verdict: u32,
    mark: Option<u32>,
    sequence: u32,
) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(48);
    let start = netlink::put_message_header(
        &mut buffer,
        (netlink::NFNL_SUBSYS_QUEUE << 8) | NFQA_MSG_VERDICT,
        netlink::NLM_F_REQUEST,
        sequence,
        0,
        QUEUE_NUM,
    );
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&verdict.to_be_bytes());
    header[4..].copy_from_slice(&packet_id.to_be_bytes());
    netlink::put_attribute(&mut buffer, NFQA_VERDICT_HDR, &header);
    if let Some(mark) = mark {
        netlink::put_attribute_be32(&mut buffer, NFQA_MARK, mark);
    }
    netlink::seal_message(&mut buffer, start);
    buffer
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use bytes::Bytes;

    use super::*;

    fn decode_verdict(encoded: Vec<u8>) -> (Vec<(u16, Bytes)>, u16) {
        let message = netlink::messages(Bytes::from(encoded))
            .next()
            .unwrap()
            .unwrap();
        let queue = u16::from_be_bytes(message.body[2..4].try_into().unwrap());
        let attributes = netlink::attributes(message.body.slice(netlink::NFGENMSG_LEN..))
            .map(|attribute| {
                let attribute = attribute.unwrap();
                (attribute.kind, attribute.payload)
            })
            .collect();
        (attributes, queue)
    }

    #[test]
    fn marked_accept_has_no_priority_attribute() {
        let (attributes, queue) = decode_verdict(build_verdict_message(
            0x0102_0304,
            NF_ACCEPT,
            Some(0x0012_3400),
            7,
        ));
        assert_eq!(queue, QUEUE_NUM);
        assert_eq!(attributes.len(), 2);
        assert_eq!(attributes[0].0, NFQA_VERDICT_HDR);
        assert_eq!(attributes[0].1.as_ref(), &[0, 0, 0, 1, 1, 2, 3, 4]);
        assert_eq!(attributes[1].0, NFQA_MARK);
        assert_eq!(attributes[1].1.as_ref(), &[0, 0x12, 0x34, 0]);
        assert!(attributes.iter().all(|(kind, _)| *kind != 21));
    }

    #[test]
    fn guard_commits_once_and_drop_defaults_to_nf_drop() {
        let (socket, reader, _fatal) = QueueSocket::for_test();
        let tracker = GuardTracker::new();
        let mut accepted = VerdictGuard::new(Arc::clone(&socket), 11, Arc::clone(&tracker));
        accepted.accept(0x400).expect("accept verdict");
        assert!(matches!(
            accepted.drop_packet(),
            Err(VerdictError::AlreadyCommitted)
        ));
        let accepted_message = netlink::recv_datagram(reader.as_raw_fd(), 128).unwrap();
        let accepted_message = netlink::messages(accepted_message).next().unwrap().unwrap();
        let accepted_attributes =
            netlink::attributes(accepted_message.body.slice(netlink::NFGENMSG_LEN..))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        assert_eq!(
            &accepted_attributes[0].payload[..4],
            &NF_ACCEPT.to_be_bytes()
        );
        drop(accepted);

        let uncommitted = VerdictGuard::new(socket, 12, Arc::clone(&tracker));
        drop(uncommitted);
        let dropped_message = netlink::recv_datagram(reader.as_raw_fd(), 128).unwrap();
        let dropped_message = netlink::messages(dropped_message).next().unwrap().unwrap();
        let dropped_attributes =
            netlink::attributes(dropped_message.body.slice(netlink::NFGENMSG_LEN..))
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        assert_eq!(&dropped_attributes[0].payload[..4], &NF_DROP.to_be_bytes());
        assert_eq!(
            Arc::strong_count(&tracker),
            1,
            "both guards released their tracker ownership"
        );
    }

    #[test]
    fn failed_verdict_send_is_fatal_and_cannot_be_retried() {
        let (socket, reader, mut fatal) = QueueSocket::for_test();
        let tracker = GuardTracker::new();
        socket.mark_closed();
        let mut guard = VerdictGuard::new(socket, 13, Arc::clone(&tracker));

        let error = guard.accept(0x400).expect_err("closed verdict socket");
        assert_eq!(
            error.to_string(),
            "verdict send failed: NFQUEUE verdict socket is closed"
        );
        assert!(matches!(
            guard.drop_packet(),
            Err(VerdictError::AlreadyCommitted)
        ));
        let fatal_error = fatal.try_recv().expect("verdict failure is process-fatal");
        assert!(matches!(
            fatal_error,
            crate::FatalError::VerdictSocket { error }
                if error == "NFQUEUE verdict socket is closed"
        ));

        drop(guard);
        let current = unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_GETFL) };
        assert!(current >= 0);
        assert_eq!(
            unsafe {
                libc::fcntl(
                    reader.as_raw_fd(),
                    libc::F_SETFL,
                    current | libc::O_NONBLOCK,
                )
            },
            0
        );
        let retry = netlink::recv_datagram(reader.as_raw_fd(), 128).unwrap_err();
        assert_eq!(retry.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(Arc::strong_count(&tracker), 1);
    }
}
